/*
 * Memory Bus Storage backed block device driver.
 *
 * Copyright (C) 2018 Yongseob Lee
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, drivers/block/brd.c,
 * drivers/nvdimm/pmem.c, and drivers/block/loop.c, 
 * copyright of their respective owners.
 */

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mempolicy.h>
//#ifdef CONFIG_BLK_DEV_MBS_DAX
#include <linux/pfn_t.h>
#include <linux/dax.h>
#include <linux/uio.h>
//#endif

#include <linux/memblock.h>
#include <linux/uaccess.h>

#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)
//#define MBSDISK_MAJOR	333
extern struct memblock memblock;
extern void *vmalloc_mbs(unsigned long size, int node, gfp_t flags);

/*
 * Each block mbsdisk device has a radix_tree mbs_pages of pages that stores
 * the pages containing the block device's contents. A mbs page's ->index is
 * its offset in PAGE_SIZE units. This is similar to, but in no way connected
 * with, the kernel's pagecache or buffer cache (which sit above our block
 * device).
 */
struct mbs_device {
	int		mbs_number;

	struct request_queue	*mbs_queue;
	struct gendisk		*mbs_disk;
//#ifdef CONFIG_BLK_DEV_MBS_DAX
	struct dax_device	*dax_dev;
//#endif
	struct list_head	mbs_list;

	/*
	 * Backing store of pages and lock to protect it. This is the contents
	 * of the block device.
	 */
	spinlock_t		mbs_lock;
	struct radix_tree_root	mbs_pages;
};

/*
 * Look up and return a mbs's page for a given sector.
 */
static DEFINE_MUTEX(mbs_mutex);
static struct page *mbs_lookup_page(struct mbs_device *mbs, sector_t sector)
{
	pgoff_t idx;
	struct page *page;

	/*
	 * The page lifetime is protected by the fact that we have opened the
	 * device node -- mbs pages will never be deleted under us, so we
	 * don't need any further locking or refcounting.
	 *
	 * This is strictly true for the radix-tree nodes as well (ie. we
	 * don't actually need the rcu_read_lock()), however that is not a
	 * documented feature of the radix-tree API so it is better to be
	 * safe here (we don't have total exclusion from radix tree updates
	 * here, only deletes).
	 */
	rcu_read_lock();
	idx = sector >> PAGE_SECTORS_SHIFT; /* sector to page index */
	page = radix_tree_lookup(&mbs->mbs_pages, idx);
	rcu_read_unlock();

	BUG_ON(page && page->index != idx);

	return page;
}

/*
 * Look up and return a mbs's page for a given sector.
 * If one does not exist, allocate an empty page, and insert that. Then
 * return it.
 */
static struct page *mbs_insert_page(struct mbs_device *mbs, sector_t sector)
{
	pgoff_t idx;
	struct page *page;
	gfp_t gfp_flags;

	page = mbs_lookup_page(mbs, sector);
	if (page)
		return page;

	/*
	 * Must use NOIO because we don't want to recurse back into the
	 * block or filesystem layers from page reclaim.
	 *
	 * Cannot support DAX and highmem, because our ->direct_access
	 * routine for DAX must return memory that is always addressable.
	 * If DAX was reworked to use pfns and kmap throughout, this
	 * restriction might be able to be lifted.
	 */
	//gfp_flags = GFP_NOIO | __GFP_ZERO;
	//gfp_flags = __GFP_PRAM;
	//gfp_flags = __GFP_PRAM | __GFP_THISNODE;
	//gfp_flags = GFP_NOIO | __GFP_ZERO | __GFP_PRAM | __GFP_THISNODE;
	//gfp_flags = GFP_NOIO | __GFP_ZERO |  __GFP_THISNODE;
	gfp_flags = GFP_NOIO | __GFP_ZERO;
#ifndef CONFIG_BLK_DEV_MBS_DAX
//	gfp_flags |= __GFP_HIGHMEM;
#endif
//	;struct mempolicy *pol = current->mempolicy;
//	pol->refcnt = ATOMIC_INIT(1);
//	pol->mode = MPOL_INTERLEAVE;
//	pol->flags = MPOL_F_LOCAL ;
//	current->mempolicy = pol;
//	do_set_mempolicy(MPOL_INTERLEAVE,0,NULL);
	page = alloc_page(gfp_flags);
//	page = __alloc_pages_nodemask(gfp_flags,0,numa_node_id(),numa_node_id());
	//page = vmalloc_mbs(memblock.pram.total_size, NUMA_NO_NODE, gfp_flags);
	//page = vmalloc_mbs(4096, NUMA_NO_NODE, gfp_flags);
	if (!page)
		return NULL;

	if (radix_tree_preload(GFP_NOIO)) {
		__free_page(page);
		return NULL;
	}

	spin_lock(&mbs->mbs_lock);
	idx = sector >> PAGE_SECTORS_SHIFT;
	page->index = idx;
	if (radix_tree_insert(&mbs->mbs_pages, idx, page)) {
		__free_page(page);
		page = radix_tree_lookup(&mbs->mbs_pages, idx);
		BUG_ON(!page);
		BUG_ON(page->index != idx);
	}
	spin_unlock(&mbs->mbs_lock);

	radix_tree_preload_end();

	return page;
}

/*
 * Free all backing store pages and radix tree. This must only be called when
 * there are no other users of the device.
 */
#define FREE_BATCH 16
static void mbs_free_pages(struct mbs_device *mbs)
{
	unsigned long pos = 0;
	struct page *pages[FREE_BATCH];
	int nr_pages;

	do {
		int i;

		nr_pages = radix_tree_gang_lookup(&mbs->mbs_pages,
				(void **)pages, pos, FREE_BATCH);

		for (i = 0; i < nr_pages; i++) {
			void *ret;

			BUG_ON(pages[i]->index < pos);
			pos = pages[i]->index;
			ret = radix_tree_delete(&mbs->mbs_pages, pos);
			BUG_ON(!ret || ret != pages[i]);
			__free_page(pages[i]);
		}

		pos++;

		/*
		 * This assumes radix_tree_gang_lookup always returns as
		 * many pages as possible. If the radix-tree code changes,
		 * so will this have to.
		 */
	} while (nr_pages == FREE_BATCH);
}

/*
 * copy_to_mbs_setup must be called before copy_to_mbs. It may sleep.
 */
static int copy_to_mbs_setup(struct mbs_device *mbs, sector_t sector, size_t n)
{
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	if (!mbs_insert_page(mbs, sector))
		return -ENOSPC;
	if (copy < n) {
		sector += copy >> SECTOR_SHIFT;
		if (!mbs_insert_page(mbs, sector))
			return -ENOSPC;
	}
	return 0;
}

/*
 * Copy n bytes from src to the mbs starting at sector. Does not sleep.
 */
static void copy_to_mbs(struct mbs_device *mbs, const void *src,
			sector_t sector, size_t n)
{
	struct page *page;
	void *dst;
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = mbs_lookup_page(mbs, sector);
	BUG_ON(!page);

	dst = kmap_atomic(page);
	memcpy(dst + offset, src, copy);
	kunmap_atomic(dst);

	if (copy < n) {
		src += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = mbs_lookup_page(mbs, sector);
		BUG_ON(!page);

		dst = kmap_atomic(page);
		memcpy(dst, src, copy);
		kunmap_atomic(dst);
	}
}

/*
 * Copy n bytes to dst from the mbs starting at sector. Does not sleep.
 */
static void copy_from_mbs(void *dst, struct mbs_device *mbs,
			sector_t sector, size_t n)
{
	struct page *page;
	void *src;
	unsigned int offset = (sector & (PAGE_SECTORS-1)) << SECTOR_SHIFT;
	size_t copy;

	copy = min_t(size_t, n, PAGE_SIZE - offset);
	page = mbs_lookup_page(mbs, sector);
	if (page) {
		src = kmap_atomic(page);
		memcpy(dst, src + offset, copy);
		kunmap_atomic(src);
	} else
		memset(dst, 0, copy);

	if (copy < n) {
		dst += copy;
		sector += copy >> SECTOR_SHIFT;
		copy = n - copy;
		page = mbs_lookup_page(mbs, sector);
		if (page) {
			src = kmap_atomic(page);
			memcpy(dst, src, copy);
			kunmap_atomic(src);
		} else
			memset(dst, 0, copy);
	}
}

/*
 * Process a single bvec of a bio.
 */
static int mbs_do_bvec(struct mbs_device *mbs, struct page *page,
			unsigned int len, unsigned int off, bool is_write,
			sector_t sector)
{
	void *mem;
	int err = 0;

	if (is_write) {
		err = copy_to_mbs_setup(mbs, sector, len);
		if (err)
			goto out;
	}

	mem = kmap_atomic(page);
	if (!is_write) {
		copy_from_mbs(mem + off, mbs, sector, len);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		copy_to_mbs(mbs, mem + off, sector, len);
	}
	kunmap_atomic(mem);

out:
	return err;
}

static blk_qc_t mbs_make_request(struct request_queue *q, struct bio *bio)
{
	struct mbs_device *mbs = bio->bi_disk->private_data;
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bio->bi_disk))
		goto io_error;

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		int err;

		err = mbs_do_bvec(mbs, bvec.bv_page, len, bvec.bv_offset,
					op_is_write(bio_op(bio)), sector);
		if (err)
			goto io_error;
		sector += len >> SECTOR_SHIFT;
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;
io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static int mbs_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, bool is_write)
{
	struct mbs_device *mbs = bdev->bd_disk->private_data;
	int err;

	if (PageTransHuge(page))
		return -ENOTSUPP;
	err = mbs_do_bvec(mbs, page, PAGE_SIZE, 0, is_write, sector);
	page_endio(page, is_write, err);
	return err;
}

//#ifdef CONFIG_BLK_DEV_MBS_DAX
static long __mbs_direct_access(struct mbs_device *mbs, pgoff_t pgoff,
		long nr_pages, void **kaddr, pfn_t *pfn)
{
	struct page *page;

	if (!mbs)
		return -ENODEV;
	page = mbs_insert_page(mbs, (sector_t)pgoff << PAGE_SECTORS_SHIFT);
	if (!page)
		return -ENOSPC;
	*kaddr = page_address(page);
	*pfn = page_to_pfn_t(page);
	//*pfn = memblock.pram.region.base;

	return 1;
}

static long mbs_dax_direct_access(struct dax_device *dax_dev,
		pgoff_t pgoff, long nr_pages, void **kaddr, pfn_t *pfn)
{
	struct mbs_device *mbs = dax_get_private(dax_dev);

	return __mbs_direct_access(mbs, pgoff, nr_pages, kaddr, pfn);
}

static size_t mbs_dax_copy_from_iter(struct dax_device *dax_dev, pgoff_t pgoff,
		void *addr, size_t bytes, struct iov_iter *i)
{
	return copy_from_iter(addr, bytes, i);
}

static const struct dax_operations mbs_dax_ops = {
	.direct_access = mbs_dax_direct_access,
	.copy_from_iter = mbs_dax_copy_from_iter,
};
//#endif

static const struct block_device_operations mbs_fops = {
	.owner =		THIS_MODULE,
	.rw_page =		mbs_rw_page,
};

/*
 * And now the modules code and kernel interface.
 */
//static int mbs_nr = CONFIG_BLK_DEV_MBS_COUNT;
static int mbs_nr = 1;
module_param(mbs_nr, int, S_IRUGO);
MODULE_PARM_DESC(mbs_nr, "Maximum number of mbs devices");

//unsigned long mbs_size = CONFIG_BLK_DEV_MBS_SIZE;
unsigned long mbs_size = 67108864 ;
module_param(mbs_size, ulong, S_IRUGO);
MODULE_PARM_DESC(mbs_size, "Size of each MBS disk in kbytes.");

static int max_part = 1;
module_param(max_part, int, S_IRUGO);
MODULE_PARM_DESC(max_part, "Num Minors to reserve between devices");

MODULE_LICENSE("GPL");

#ifndef MODULE
/* Legacy boot options - nonmodular */
static int __init mbsdisk_size(char *str)
{
	mbs_size = simple_strtol(str, NULL, 0);
	return 1;
}
__setup("mbsdisk_size=", mbsdisk_size);
#endif

/*
 * The device scheme is derived from loop.c. Keep them in synch where possible
 * (should share code eventually).
 */
static LIST_HEAD(mbs_devices);
static DEFINE_MUTEX(mbs_devices_mutex);

static struct mbs_device *mbs_alloc(int i)
{
	struct mbs_device *mbs;
	struct gendisk *disk;

	mbs_size = memblock.pram.total_size/1024;//convert to kbytes
//	mbs = kzalloc(sizeof(*mbs), __GFP_PRAM );
//	mbs = kzalloc(sizeof(*mbs), __GFP_PRAM | __GFP_THISNODE);
	mbs = kzalloc(sizeof(*mbs), GFP_KERNEL);
	if (!mbs)
		goto out;
	mbs->mbs_number		= i;
	spin_lock_init(&mbs->mbs_lock);
	INIT_RADIX_TREE(&mbs->mbs_pages, GFP_ATOMIC);

	mbs->mbs_queue = blk_alloc_queue(GFP_KERNEL);
	if (!mbs->mbs_queue)
		goto out_free_dev;

	blk_queue_make_request(mbs->mbs_queue, mbs_make_request);
	blk_queue_max_hw_sectors(mbs->mbs_queue, 1024);
	//blk_queue_bounce_limit(mbs->mbs_queue, BLK_BOUNCE_ANY);

	/* This is so fdisk will align partitions on 4k, because of
	 * direct_access API needing 4k alignment, returning a PFN
	 * (This is only a problem on very small devices <= 4M,
	 *  otherwise fdisk will align on 1M. Regardless this call
	 *  is harmless)
	 */
	blk_queue_physical_block_size(mbs->mbs_queue, PAGE_SIZE);
	disk = mbs->mbs_disk = alloc_disk(max_part);
	if (!disk)
		goto out_free_queue;
	disk->major		= MBSDISK_MAJOR;
	disk->first_minor	= i * max_part;
	disk->fops		= &mbs_fops;
	disk->private_data	= mbs;
	disk->queue		= mbs->mbs_queue;
	disk->flags		= GENHD_FL_EXT_DEVT;
	sprintf(disk->disk_name, "mbs%d", i);
	set_capacity(disk, mbs_size * 2);

//#ifdef CONFIG_BLK_DEV_MBS_DAX
	queue_flag_set_unlocked(QUEUE_FLAG_DAX, mbs->mbs_queue);
	mbs->dax_dev = alloc_dax(mbs, disk->disk_name, &mbs_dax_ops);
	if (!mbs->dax_dev)
		goto out_free_inode;
//#endif


	return mbs;

//#ifdef CONFIG_BLK_DEV_MBS_DAX
out_free_inode:
	kill_dax(mbs->dax_dev);
	put_dax(mbs->dax_dev);
//#endif
out_free_queue:
	blk_cleanup_queue(mbs->mbs_queue);
out_free_dev:
	kfree(mbs);
out:
	return NULL;
}

static void mbs_free(struct mbs_device *mbs)
{
	put_disk(mbs->mbs_disk);
	blk_cleanup_queue(mbs->mbs_queue);
	mbs_free_pages(mbs);
	kfree(mbs);
}

static struct mbs_device *mbs_init_one(int i, bool *new)
{
	struct mbs_device *mbs;

	*new = false;
	list_for_each_entry(mbs, &mbs_devices, mbs_list) {
		if (mbs->mbs_number == i)
			goto out;
	}

	mbs = mbs_alloc(i);
	if (mbs) {
		add_disk(mbs->mbs_disk);
		list_add_tail(&mbs->mbs_list, &mbs_devices);
	}
	*new = true;
out:
	return mbs;
}

static void mbs_del_one(struct mbs_device *mbs)
{
	list_del(&mbs->mbs_list);
//#ifdef CONFIG_BLK_DEV_MBS_DAX
	kill_dax(mbs->dax_dev);
	put_dax(mbs->dax_dev);
//#endif
	del_gendisk(mbs->mbs_disk);
	mbs_free(mbs);
}

static struct kobject *mbs_probe(dev_t dev, int *part, void *data)
{
	struct mbs_device *mbs;
	struct kobject *kobj;
	bool new;

	mutex_lock(&mbs_devices_mutex);
	mbs = mbs_init_one(MINOR(dev) / max_part, &new);
	kobj = mbs ? get_disk(mbs->mbs_disk) : NULL;
	mutex_unlock(&mbs_devices_mutex);

	if (new)
		*part = 0;

	return kobj;
}

static int __init mbs_init(void)
{
	struct mbs_device *mbs, *next;
	int i;

	/*
	 * mbs module now has a feature to instantiate underlying device
	 * structure on-demand, provided that there is an access dev node.
	 *
	 * (1) if mbs_nr is specified, create that many upfront. else
	 *     it defaults to CONFIG_BLK_DEV_MBS_COUNT
	 * (2) User can further extend mbs devices by create dev node themselves
	 *     and have kernel automatically instantiate actual device
	 *     on-demand. Example:
	 *		mknod /path/devnod_name b 1 X	# 1 is the rd major
	 *		fdisk -l /path/devnod_name
	 *	If (X / max_part) was not already created it will be created
	 *	dynamically.
	 */

	if (register_blkdev(MBSDISK_MAJOR, "mbsdisk"))
		return -EIO;

	if (unlikely(!max_part))
		max_part = 1;

	for (i = 0; i < mbs_nr; i++) {
		mbs = mbs_alloc(i);
		if (!mbs)
			goto out_free;
		list_add_tail(&mbs->mbs_list, &mbs_devices);
	}

	/* point of no return */

	list_for_each_entry(mbs, &mbs_devices, mbs_list)
		add_disk(mbs->mbs_disk);

	blk_register_region(MKDEV(MBSDISK_MAJOR, 0), 1UL << MINORBITS,
				  THIS_MODULE, mbs_probe, NULL, NULL);

	pr_info("mbs: module loaded\n");
	pr_info("mbs zone total size : [ %#018Lx ]\n",
			(u64)memblock.pram.total_size);
	return 0;

out_free:
	list_for_each_entry_safe(mbs, next, &mbs_devices, mbs_list) {
		list_del(&mbs->mbs_list);
		mbs_free(mbs);
	}
	unregister_blkdev(MBSDISK_MAJOR, "mbsdisk");

	pr_info("mbs: module NOT loaded !!!\n");
	return -ENOMEM;
}

static void __exit mbs_exit(void)
{
	struct mbs_device *mbs, *next;

	list_for_each_entry_safe(mbs, next, &mbs_devices, mbs_list)
		mbs_del_one(mbs);

	blk_unregister_region(MKDEV(MBSDISK_MAJOR, 0), 1UL << MINORBITS);
	unregister_blkdev(MBSDISK_MAJOR, "mbsdisk");

	pr_info("mbs: module unloaded\n");
}

module_init(mbs_init);
module_exit(mbs_exit);

