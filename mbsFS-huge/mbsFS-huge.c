/*
 * simple FS for Memory Bus connected Storage
 * Memory Bus-connected Storage File System
 * Copyright (C) 2018 Yongseob Lee
 *
 * Resizable virtual memory filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *		 2000 Transmeta Corp.
 *		 2000-2001 Christoph Rohland
 *		 2000-2001 SAP AG
 *		 2002 Red Hat Inc.
 * Copyright (C) 2002-2011 Hugh Dickins.
 * Copyright (C) 2011 Google Inc.
 * Copyright (C) 2002-2005 VERITAS Software Corporation.
 * Copyright (C) 2004 Andi Kleen, SuSE Labs
 *
 * Extended attribute support for tmpfs:
 * Copyright (c) 2004, Luke Kenneth Casson Leighton <lkcl@lkcl.net>
 * Copyright (c) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 * tiny-shmem:
 * Copyright (c) 2004, 2008 Matt Mackall <mpm@selenic.com>
 *
 * This file is released under the GPL.
 */

//#########################
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
//#########################
#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/ramfs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/uio.h>
#include <linux/khugepaged.h>
//#include <linux/hugetlb.h>
/***************************/
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cpuset.h>
#include <asm/tlbflush.h> /* for arch/microblaze update_mmu_cache() */
/***************************/

static struct vfsmount *mbsfs_mnt;

#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/mman.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/pagevec.h>
#include <linux/percpu_counter.h>
#include <linux/falloc.h>
#include <linux/splice.h>
#include <linux/security.h>
#include <linux/swapops.h>
#include <linux/mempolicy.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/migrate.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <uapi/linux/memfd.h>
#include <linux/userfaultfd_k.h>
#include <linux/rmap.h>
#include <linux/uuid.h>

#include <asm/pgtable.h>
//#########################
//#########################
//#########################
#include <linux/memblock.h>
#include "mbs_fs.h"
#include "internal.h"
#define MBSFS_MAGIC             0x20181231      //random number 
#define ORDERS			0		//for accounting test
#define INTERLEAVE	0
#define LOCAL		1
#define BLOCKS_PER_PAGE  ( ( PAGE_SIZE << ORDERS )/512)
#define VM_ACCT(size)    (PAGE_ALIGN(size) >> PAGE_SHIFT)

/* Pretend that each entry is of this size in directory's i_size */
#define BOGO_DIRENT_SIZE 20

/* Symlink up to this size is kmalloc'ed instead of using a swappable page */
#define SHORT_SYMLINK_LEN 128
/* below will be disappeared */
#ifdef CONFIG_MBSFS_XATTR
#undef CONFIG_MBSFS_XATTR
#endif
#ifdef CONFIG_MBSFS_POSIX_ACL
#undef CONFIG_MBSFS_POSIX_ACL
#endif
#ifdef CONFIG_MIGRATION
#undef CONFIG_MIGRATION
#endif
/* above will be disappeared */
//<<<2018.05.18 compile waring
//extern s32 vm_committed_as_batch;
//>>>
extern struct memblock memblock;
extern struct mempolicy * mpol_mbsfs_policy_lookup(struct mbsfs_policy *sp, unsigned long idx);
extern int mpol_set_mbsfs_policy(struct mbsfs_policy *info,struct vm_area_struct *vma, struct mempolicy *npol);
extern int user_pram_lock(size_t size, struct user_struct *user);
extern void user_pram_unlock(size_t size, struct user_struct *user);
extern void lru_add_drain(void);
extern void lru_add_drain_all(void);
extern struct mempolicy default_pram_policy;
extern ssize_t generic_file_buffered_read(struct kiocb *iocb,
		struct iov_iter *iter, ssize_t written);
extern struct page *mbsfs__page_cache_alloc(gfp_t gfp);
//extern struct file *hugetlb_file_setup(const char *name, size_t size, vm_flags_t acct,
//				struct user_struct **user, int creat_flags,
//				int page_size_log);

#define is_file_hugepages(file)			false
//####################
//####################
//####################
//####################
#if 0
static unsigned long mbsfs_mmu_get_unmapped_area(struct file *file,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

static inline struct file *
hugetlb_file_setup(const char *name, size_t size, vm_flags_t acctflag,
		struct user_struct **user, int creat_flags,
		int page_size_log)
{
	return ERR_PTR(-ENOSYS);
}
#endif
//static inline void prep_transhuge_page(struct page *page) {}
/*
 * mbsfs_fallocate communicates with mbsfs_fault or mbsFS_writepage via
 * inode->i_private (with i_mutex making sure that it has only one user at
 * a time): we would prefer not to enlarge the mbsFS inode just for that.
 */
unsigned long totalpram_pages;
static unsigned long mbsfs_default_max_blocks(void)
{
	totalpram_pages=memblock.pram.total_size / PAGE_SIZE;//convert to pages
	//totalpram_pages=totalram_pages;
	return totalpram_pages; 
	return totalpram_pages / 2;
}

static unsigned long mbsfs_default_max_inodes(void)
{
	totalpram_pages=memblock.pram.total_size / PAGE_SIZE;//convert to pages
//	totalpram_pages=totalram_pages;
	return min(totalpram_pages - totalhigh_pages, totalpram_pages);
}

struct mbsfs_falloc {
	wait_queue_head_t *waitq; /* faults into hole wait for punch to end */
	pgoff_t start;		/* start of range currently being fallocated */
	pgoff_t next;		/* the next page offset to be fallocated */
	pgoff_t nr_falloced;	/* how many new pages have been fallocated */
	pgoff_t nr_unswapped;	/* how often writepage refused to swap out */
};

#if 0
static bool mbsFS_should_replace_page(struct page *page, gfp_t gfp);
static int mbsFS_replace_page(struct page **pagep, gfp_t gfp,
		struct mbsfs_inode_info *info, pgoff_t index);
#endif
static int mbsfs_getpage_gfp(struct inode *inode, pgoff_t index,
		struct page **pagep, enum mbs_type mbstype,
		gfp_t gfp, struct vm_area_struct *vma,
		struct vm_fault *vmf, int *fault_type);

int mbsfs_getpage(struct inode *inode, pgoff_t index,
		struct page **pagep, enum mbs_type mbstype)
{
	return mbsfs_getpage_gfp(inode, index, pagep, mbstype,
			mapping_gfp_mask(inode->i_mapping), NULL, NULL, NULL);
}

/*
 * mbsFS_file_setup pre-accounts the whole fixed size of a VM object,
 * for MBS memory and for MBS anonymous (/dev/zero) mappings
 * (unless MAP_NORESERVE and sysctl_overcommit_memory <= 1),
 * consistent with the pre-accounting of private mappings ...
 */
static inline int mbsFS_acct_size(unsigned long flags, loff_t size)
{
	return (flags & VM_NORESERVE) ?
		0 : security_vm_enough_memory_mm(current->mm, VM_ACCT(size));
}

static inline void mbsfs_unacct_size(unsigned long flags, loff_t size)
{
	if (!(flags & VM_NORESERVE))
		vm_unacct_memory(VM_ACCT(size));
}

static inline int mbsFS_reacct_size(unsigned long flags,
		loff_t oldsize, loff_t newsize)
{
	if (!(flags & VM_NORESERVE)) {
		if (VM_ACCT(newsize) > VM_ACCT(oldsize))
			return security_vm_enough_memory_mm(current->mm,
					VM_ACCT(newsize) - VM_ACCT(oldsize));
		else if (VM_ACCT(newsize) < VM_ACCT(oldsize))
			vm_unacct_memory(VM_ACCT(oldsize) - VM_ACCT(newsize));
	}
	return 0;
}

/*
 * ... whereas mbsfs objects are accounted incrementally as
 * pages are allocated, in order to allow large sparse files.
 * mbsfs_getpage reports mbsFS_acct_block failure as -ENOSPC not -ENOMEM,
 * so that a failure on a sparse mbsfs mapping will give SIGBUS not OOM.
 */
static inline int mbsFS_acct_block(unsigned long flags, long pages)
{
	if (!(flags & VM_NORESERVE))
		return 0;

	return security_vm_enough_memory_mm(current->mm,
			pages * VM_ACCT(PAGE_SIZE));
}
#if 0
#endif
static inline void mbsfs_unacct_blocks(unsigned long flags, long pages)
{
	if (flags & VM_NORESERVE)
		vm_unacct_memory(pages * VM_ACCT(PAGE_SIZE));
}

static inline bool mbsFS_inode_acct_block(struct inode *inode, long pages)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	struct mbsfs_sb_info *sbinfo = MBS_SB(inode->i_sb);

	if (mbsFS_acct_block(info->flags, pages))
		return false;

	if (sbinfo->max_blocks) {
		if (percpu_counter_compare(&sbinfo->used_blocks,
					sbinfo->max_blocks - pages) > 0)
			goto unacct;
		percpu_counter_add(&sbinfo->used_blocks, pages);
	}

	return true;

unacct:
	mbsfs_unacct_blocks(info->flags, pages);
	return false;
}
#if 0
#endif
static inline void mbsfs_inode_unacct_blocks(struct inode *inode, long pages)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	struct mbsfs_sb_info *sbinfo = MBS_SB(inode->i_sb);

	if (sbinfo->max_blocks)
		percpu_counter_sub(&sbinfo->used_blocks, pages);
	mbsfs_unacct_blocks(info->flags, pages);
}

static const struct super_operations mbsfs_ops;
static const struct address_space_operations mbsfs_aops;
static const struct file_operations mbsfs_file_operations;
static const struct inode_operations mbsfs_inode_operations;
static const struct inode_operations mbsfs_dir_inode_operations;
static const struct inode_operations mbsfs_special_inode_operations;
static const struct vm_operations_struct mbsfs_vm_ops;
static struct file_system_type mbsfs_fs_type;
static int mbsfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname);

#if 0
bool vma_is_mbsFS(struct vm_area_struct *vma)
{
	return vma->vm_ops == &mbsfs_vm_ops;
}

static LIST_HEAD(mbsFS_swaplist);
static DEFINE_MUTEX(mbsFS_swaplist_mutex);
#endif

static int mbsfs_reserve_inode(struct super_block *sb)
{
	struct mbsfs_sb_info *sbinfo = MBS_SB(sb);
	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		if (!sbinfo->free_inodes) {
			spin_unlock(&sbinfo->stat_lock);
			return -ENOSPC;
		}
		sbinfo->free_inodes--;
		spin_unlock(&sbinfo->stat_lock);
	}
	return 0;
}
static void mbsfs_free_inode(struct super_block *sb)
{
	struct mbsfs_sb_info *sbinfo = MBS_SB(sb);
	if (sbinfo->max_inodes) {
		spin_lock(&sbinfo->stat_lock);
		sbinfo->free_inodes++;
		spin_unlock(&sbinfo->stat_lock);
	}
}

/**
 * mbsfs_recalc_inode - recalculate the block usage of an inode
 * @inode: inode to recalc
 *
 * We have to calculate the free blocks since the mm can drop
 * undirtied hole pages behind our back.
 *
 * But normally   info->alloced == inode->i_mapping->nrpages + info->swapped
 * So mm freed is info->alloced - (inode->i_mapping->nrpages + info->swapped)
 *
 * It has to be called with the spinlock held.
 */
static void mbsfs_recalc_inode(struct inode *inode)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	long freed;

	//freed = info->alloced - info->swapped - inode->i_mapping->nrpages;
	freed = info->alloced - inode->i_mapping->nrpages;
	if (freed > 0) {
		info->alloced -= freed;
		inode->i_blocks -= freed * BLOCKS_PER_PAGE;
		mbsfs_inode_unacct_blocks(inode, freed);
	}
}
#if 0
bool mbsFS_charge(struct inode *inode, long pages)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	unsigned long flags;

	if (!mbsFS_inode_acct_block(inode, pages))
		return false;

	spin_lock_irqsave(&info->lock, flags);
	info->alloced += pages;
	inode->i_blocks += pages * BLOCKS_PER_PAGE;
	mbsfs_recalc_inode(inode);
	spin_unlock_irqrestore(&info->lock, flags);
	inode->i_mapping->nrpages += pages;

	return true;
}

void mbsFS_uncharge(struct inode *inode, long pages)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	unsigned long flags;

	spin_lock_irqsave(&info->lock, flags);
	info->alloced -= pages;
	inode->i_blocks -= pages * BLOCKS_PER_PAGE;
	mbsfs_recalc_inode(inode);
	spin_unlock_irqrestore(&info->lock, flags);

	mbsfs_inode_unacct_blocks(inode, pages);
}
#endif
/*
 * Replace item expected in radix tree by a new item, while holding tree lock.
 */
static int mbsfs_radix_tree_replace(struct address_space *mapping,
		pgoff_t index, void *expected, void *replacement)
{
	struct radix_tree_node *node;
	void **pslot;
	void *item;

	VM_BUG_ON(!expected);
	VM_BUG_ON(!replacement);
	item = __radix_tree_lookup(&mapping->page_tree, index, &node, &pslot);
	if (!item)
		return -ENOENT;
	if (item != expected)
		return -ENOENT;
	__radix_tree_replace(&mapping->page_tree, node, pslot,
			replacement, NULL, NULL);
	return 0;
}
#if 0
/*
 * Sometimes, before we decide whether to proceed or to fail, we must check
 * that an entry was not already brought back from swap by a racing thread.
 *
 * Checking page is not enough: by the time a SwapCache page is locked, it
 * might be reused, and again be SwapCache, using the same swap as before.
 */
static bool mbsFS_confirm_swap(struct address_space *mapping,
		pgoff_t index, swp_entry_t swap)
{
	void *item;

	rcu_read_lock();
	item = radix_tree_lookup(&mapping->page_tree, index);
	rcu_read_unlock();
	return item == swp_to_radix_entry(swap);
}
#endif
/*
 * Definitions for "huge mbsfs": mbsfs mounted with the huge= option
 *
 * MBS_HUGE_NEVER:
 *	disables huge pages for the mount;
 * MBS_HUGE_ALWAYS:
 *	enables huge pages for the mount;
 * MBS_HUGE_WITHIN_SIZE:
 *	only allocate huge pages if the page will be fully within i_size,
 *	also respect fadvise()/madvise() hints;
 * MBS_HUGE_ADVISE:
 *	only allocate huge pages if requested with fadvise()/madvise();
 */

#define MBS_HUGE_NEVER	0
#define MBS_HUGE_ALWAYS	1
#define MBS_HUGE_WITHIN_SIZE	2
#define MBS_HUGE_ADVISE	3

/*
 * Special values.
 * Only can be set via /sys/kernel/mm/transparent_hugepage/mbsFS_enabled:
 *
 * MBS_HUGE_DENY:
 *	disables huge on mbsfs_mnt and all mounts, for emergency use;
 * MBS_HUGE_FORCE:
 *	enables huge on mbsfs_mnt and all mounts, w/o needing option, for testing;
 *
 */
#define MBS_HUGE_DENY	(-1)
#define MBS_HUGE_FORCE	(-2)

#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
int mbsFS_huge __read_mostly;

#if defined(CONFIG_SYSFS) || defined(CONFIG_TMPFS)
static int mbsfs_parse_huge(const char *str)
{
	if (!strcmp(str, "never"))
		return MBS_HUGE_NEVER;
	if (!strcmp(str, "always"))
		return MBS_HUGE_ALWAYS;
	if (!strcmp(str, "within_size"))
		return MBS_HUGE_WITHIN_SIZE;
	if (!strcmp(str, "advise"))
		return MBS_HUGE_ADVISE;
	if (!strcmp(str, "deny"))
		return MBS_HUGE_DENY;
	if (!strcmp(str, "force"))
		return MBS_HUGE_FORCE;
	return -EINVAL;
}

static const char *mbsfs_format_huge(int huge)
{
	switch (huge) {
	case MBS_HUGE_NEVER:
		return "never";
	case MBS_HUGE_ALWAYS:
		return "always";
	case MBS_HUGE_WITHIN_SIZE:
		return "within_size";
	case MBS_HUGE_ADVISE:
		return "advise";
	case MBS_HUGE_DENY:
		return "deny";
	case MBS_HUGE_FORCE:
		return "force";
	default:
		VM_BUG_ON(1);
		return "bad_val";
	}
}
#endif

static unsigned long mbsfs_unused_huge_shrink(struct mbsfs_sb_info *sbinfo,
		struct shrink_control *sc, unsigned long nr_to_split)
{
	LIST_HEAD(list), *pos, *next;
	LIST_HEAD(to_remove);
	struct inode *inode;
	struct mbsfs_inode_info *info;
	struct page *page;
	unsigned long batch = sc ? sc->nr_to_scan : 128;
	int removed = 0, split = 0;

	if (list_empty(&sbinfo->shrinklist))
		return SHRINK_STOP;

	spin_lock(&sbinfo->shrinklist_lock);
	list_for_each_safe(pos, next, &sbinfo->shrinklist) {
		info = list_entry(pos, struct mbsfs_inode_info, shrinklist);

		/* pin the inode */
		inode = igrab(&info->vfs_inode);

		/* inode is about to be evicted */
		if (!inode) {
			list_del_init(&info->shrinklist);
			removed++;
			goto next;
		}

		/* Check if there's anything to gain */
		if (round_up(inode->i_size, PAGE_SIZE) ==
				round_up(inode->i_size, HPAGE_PMD_SIZE)) {
			list_move(&info->shrinklist, &to_remove);
			removed++;
			goto next;
		}

		list_move(&info->shrinklist, &list);
next:
		if (!--batch)
			break;
	}
	spin_unlock(&sbinfo->shrinklist_lock);

	list_for_each_safe(pos, next, &to_remove) {
		info = list_entry(pos, struct mbsfs_inode_info, shrinklist);
		inode = &info->vfs_inode;
		list_del_init(&info->shrinklist);
		iput(inode);
	}

	list_for_each_safe(pos, next, &list) {
		int ret;

		info = list_entry(pos, struct mbsfs_inode_info, shrinklist);
		inode = &info->vfs_inode;

		if (nr_to_split && split >= nr_to_split) {
			iput(inode);
			continue;
		}

		page = find_lock_page(inode->i_mapping,
				(inode->i_size & HPAGE_PMD_MASK) >> PAGE_SHIFT);
		if (!page)
			goto drop;

		if (!PageTransHuge(page)) {
			unlock_page(page);
			put_page(page);
			goto drop;
		}

		ret = split_huge_page(page);
		unlock_page(page);
		put_page(page);

		if (ret) {
			/* split failed: leave it on the list */
			iput(inode);
			continue;
		}

		split++;
drop:
		list_del_init(&info->shrinklist);
		removed++;
		iput(inode);
	}

	spin_lock(&sbinfo->shrinklist_lock);
	list_splice_tail(&list, &sbinfo->shrinklist);
	sbinfo->shrinklist_len -= removed;
	spin_unlock(&sbinfo->shrinklist_lock);

	return split;
}

static long mbsfs_unused_huge_scan(struct super_block *sb,
		struct shrink_control *sc)
{
	struct mbsfs_sb_info *sbinfo = MBS_SB(sb);

	if (!READ_ONCE(sbinfo->shrinklist_len))
		return SHRINK_STOP;

	return mbsfs_unused_huge_shrink(sbinfo, sc, 0);
}

static long mbsfs_unused_huge_count(struct super_block *sb,
		struct shrink_control *sc)
{
	struct mbsfs_sb_info *sbinfo = MBS_SB(sb);
	return READ_ONCE(sbinfo->shrinklist_len);
}

#else
#define mbsFS_huge MBS_HUGE_DENY
static unsigned long mbsfs_unused_huge_shrink(struct mbsfs_sb_info *sbinfo,
		struct shrink_control *sc, unsigned long nr_to_split)
{
	return 0;
}
#endif
/*
 * Like add_to_page_cache_locked, but error if expected item has gone.
 */
static int mbsfs_add_to_page_cache(struct page *page,
		struct address_space *mapping,
		pgoff_t index, void *expected)
{
	int error, nr = hpage_nr_pages(page);

	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(index != round_down(index, nr), page);
	//VM_BUG_ON_PAGE(!PageLocked(page), page);
	//VM_BUG_ON_PAGE(!PageSwapBacked(page), page);
	//VM_BUG_ON(expected && PageTransHuge(page));

	page_ref_add(page, nr);
	page->mapping = mapping;
	page->index = index;

	spin_lock_irq(&mapping->tree_lock);
#if 0
	if (PageTransHuge(page)) {
		void __rcu **results;
		pgoff_t idx;
		int i;

		error = 0;
		if (radix_tree_gang_lookup_slot(&mapping->page_tree,
					&results, &idx, index, 1) &&
				idx < index + HPAGE_PMD_NR) {
			error = -EEXIST;
		}

		if (!error) {
			for (i = 0; i < HPAGE_PMD_NR; i++) {
				error = radix_tree_insert(&mapping->page_tree,
						index + i, page + i);
				VM_BUG_ON(error);
			}
			count_vm_event(THP_FILE_ALLOC);
		}
	} else
#endif
		if (!expected) {
			error = radix_tree_insert(&mapping->page_tree, index, page);
		} else {
			error = mbsfs_radix_tree_replace(mapping, index, expected,
					page);
		}

	if (!error) {
		mapping->nrpages += nr;
		if (PageTransHuge(page))
			__inc_node_page_state(page, NR_SHMEM_THPS);
		//__mod_node_page_state(page_pgdat(page), NR_FILE_PAGES, nr);
		//__mod_node_page_state(page_pgdat(page), NR_SHMEM, nr);
		spin_unlock_irq(&mapping->tree_lock);
	} else {
		page->mapping = NULL;
		spin_unlock_irq(&mapping->tree_lock);
		page_ref_sub(page, nr);
	}
	return error;
}
#if 0
/*
 * Like delete_from_page_cache, but substitutes swap for page.
 */
static void mbsFS_delete_from_page_cache(struct page *page, void *radswap)
{
	struct address_space *mapping = page->mapping;
	int error;

	VM_BUG_ON_PAGE(PageCompound(page), page);

	spin_lock_irq(&mapping->tree_lock);
	error = mbsfs_radix_tree_replace(mapping, page->index, page, radswap);
	page->mapping = NULL;
	mapping->nrpages--;
	__dec_node_page_state(page, NR_FILE_PAGES);
	__dec_node_page_state(page, NR_SHMEM);
	spin_unlock_irq(&mapping->tree_lock);
	put_page(page);
	BUG_ON(error);
}
/*
 * Remove swap entry from radix tree, free the swap and its page cache.
 */
static int mbsFS_free_swap(struct address_space *mapping,
		pgoff_t index, void *radswap)
{
	void *old;

	spin_lock_irq(&mapping->tree_lock);
	old = radix_tree_delete_item(&mapping->page_tree, index, radswap);
	spin_unlock_irq(&mapping->tree_lock);
	if (old != radswap)
		return -ENOENT;
	free_swap_and_cache(radix_to_swp_entry(radswap));
	return 0;
}

/*
 * Determine (in bytes) how many of the mbsFS object's pages mapped by the
 * given offsets are swapped out.
 *
 * This is safe to call without i_mutex or mapping->tree_lock thanks to RCU,
 * as long as the inode doesn't go away and racy results are not a problem.
 */
unsigned long mbsFS_partial_swap_usage(struct address_space *mapping,
		pgoff_t start, pgoff_t end)
{
	struct radix_tree_iter iter;
	void **slot;
	struct page *page;
	unsigned long swapped = 0;

	rcu_read_lock();

	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		if (iter.index >= end)
			break;

		page = radix_tree_deref_slot(slot);

		if (radix_tree_deref_retry(page)) {
			slot = radix_tree_iter_retry(&iter);
			continue;
		}

		if (radix_tree_exceptional_entry(page))
			swapped++;

		if (need_resched()) {
			slot = radix_tree_iter_resume(slot, &iter);
			cond_resched_rcu();
		}
	}

	rcu_read_unlock();

	return swapped << PAGE_SHIFT;
}

/*
 * Determine (in bytes) how many of the mbsFS object's pages mapped by the
 * given vma is swapped out.
 *
 * This is safe to call without i_mutex or mapping->tree_lock thanks to RCU,
 * as long as the inode doesn't go away and racy results are not a problem.
 */
unsigned long mbsFS_swap_usage(struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(vma->vm_file);
	struct mbsfs_inode_info *info = MBS_I(inode);
	struct address_space *mapping = inode->i_mapping;
	unsigned long swapped;

	/* Be careful as we don't hold info->lock */
	swapped = READ_ONCE(info->swapped);

	/*
	 * The easier cases are when the mbsFS object has nothing in swap, or
	 * the vma maps it whole. Then we can simply use the stats that we
	 * already track.
	 */
	if (!swapped)
		return 0;

	if (!vma->vm_pgoff && vma->vm_end - vma->vm_start >= inode->i_size)
		return swapped << PAGE_SHIFT;

	/* Here comes the more involved part */
	return mbsFS_partial_swap_usage(mapping,
			linear_page_index(vma, vma->vm_start),
			linear_page_index(vma, vma->vm_end));
}

/*
 * SysV IPC SHM_UNLOCK restore Unevictable pages to their evictable lists.
 */
void mbsFS_unlock_mapping(struct address_space *mapping)
{
	struct pagevec pvec;
	pgoff_t indices[PAGEVEC_SIZE];
	pgoff_t index = 0;

	pagevec_init(&pvec, 0);
	/*
	 * Minor point, but we might as well stop if someone else SHM_LOCKs it.
	 */
	while (!mapping_unevictable(mapping)) {
		/*
		 * Avoid pagevec_lookup(): find_get_pages() returns 0 as if it
		 * has finished, if it hits a row of PAGEVEC_SIZE swap entries.
		 */
		pvec.nr = find_get_entries(mapping, index,
				PAGEVEC_SIZE, pvec.pages, indices);
		if (!pvec.nr)
			break;
		index = indices[pvec.nr - 1] + 1;
		pagevec_remove_exceptionals(&pvec); //	mm/swap.c
		check_move_unevictable_pages(pvec.pages, pvec.nr);
		pagevec_release(&pvec);
		cond_resched();
	}
}
#endif
/*
 * Remove range of pages and swap entries from radix tree, and free them.
 * If !unfalloc, truncate or punch hole; if unfalloc, undo failed fallocate.
 */
static void mbsfs_undo_range(struct inode *inode, loff_t lstart, loff_t lend,
		bool unfalloc)
{
	struct address_space *mapping = inode->i_mapping;
	struct mbsfs_inode_info *info = MBS_I(inode);
	pgoff_t start = (lstart + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pgoff_t end = (lend + 1) >> PAGE_SHIFT;
	unsigned int partial_start = lstart & (PAGE_SIZE - 1);
	unsigned int partial_end = (lend + 1) & (PAGE_SIZE - 1);
	struct pagevec pvec;
	pgoff_t indices[PAGEVEC_SIZE];
	//long nr_swaps_freed = 0;
	pgoff_t index;
	int i;

	if (lend == -1)
		end = -1;	/* unsigned, so actually very big */

	pagevec_init(&pvec, 0);
	index = start;
	while (index < end) {
		pvec.nr = find_get_entries(mapping, index,
				min(end - index, (pgoff_t)PAGEVEC_SIZE),
				pvec.pages, indices);
		if (!pvec.nr)
			break;
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			index = indices[i];
			if (index >= end)
				break;
#if 0
			if (radix_tree_exceptional_entry(page)) {
				if (unfalloc)
					continue;
				nr_swaps_freed += !mbsFS_free_swap(mapping,
						index, page);
				continue;
			}
#endif
			VM_BUG_ON_PAGE(page_to_pgoff(page) != index, page);

			if (!trylock_page(page))
				continue;

			if (PageTransTail(page)) {
				/* Middle of THP: zero out the page */
				clear_highpage(page);
				unlock_page(page);
				continue;
			} else if (PageTransHuge(page)) {
				if (index == round_down(end, HPAGE_PMD_NR)) {
					/*
					 * Range ends in the middle of THP:
					 * zero out the page
					 */
					clear_highpage(page);
					unlock_page(page);
					continue;
				}
				index += HPAGE_PMD_NR - 1;
				i += HPAGE_PMD_NR - 1;
			}

			if (!unfalloc || !PageUptodate(page)) {
				VM_BUG_ON_PAGE(PageTail(page), page);
				if (page_mapping(page) == mapping) {
					VM_BUG_ON_PAGE(PageWriteback(page), page);
					truncate_inode_page(mapping, page);
				}
			}
			unlock_page(page);
		}
		pagevec_remove_exceptionals(&pvec); //	mm/swap.c
		pagevec_release(&pvec);
		cond_resched();
		index++;
	}

	if (partial_start) {
		struct page *page = NULL;
		mbsfs_getpage(inode, start - 1, &page, MBS_READ);
		if (page) {
			unsigned int top = PAGE_SIZE;
			if (start > end) {
				top = partial_end;
				partial_end = 0;
			}
			zero_user_segment(page, partial_start, top);
			set_page_dirty(page);
			unlock_page(page);
			put_page(page);
		}
	}
	if (partial_end) {
		struct page *page = NULL;
		mbsfs_getpage(inode, end, &page, MBS_READ);
		if (page) {
			zero_user_segment(page, 0, partial_end);
			set_page_dirty(page);
			unlock_page(page);
			put_page(page);
		}
	}
	if (start >= end)
		return;

	index = start;
	while (index < end) {
		cond_resched();

		pvec.nr = find_get_entries(mapping, index,
				min(end - index, (pgoff_t)PAGEVEC_SIZE),
				pvec.pages, indices);
		if (!pvec.nr) {
			/* If all gone or hole-punch or unfalloc, we're done */
			if (index == start || end != -1)
				break;
			/* But if truncating, restart to make sure all gone */
			index = start;
			continue;
		}
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			index = indices[i];
			if (index >= end)
				break;
#if 0
			if (radix_tree_exceptional_entry(page)) {
				if (unfalloc)
					continue;
				if (mbsFS_free_swap(mapping, index, page)) {
					/* Swap was replaced by page: retry */
					index--;
					break;
				}
				nr_swaps_freed++;
				continue;
			}
#endif
			lock_page(page);

			if (PageTransTail(page)) {
				/* Middle of THP: zero out the page */
				clear_highpage(page);
				unlock_page(page);
				/*
				 * Partial thp truncate due 'start' in middle
				 * of THP: don't need to look on these pages
				 * again on !pvec.nr restart.
				 */
				if (index != round_down(end, HPAGE_PMD_NR))
					start++;
				continue;
			} else if (PageTransHuge(page)) {
				if (index == round_down(end, HPAGE_PMD_NR)) {
					/*
					 * Range ends in the middle of THP:
					 * zero out the page
					 */
					clear_highpage(page);
					unlock_page(page);
					continue;
				}
				index += HPAGE_PMD_NR - 1;
				i += HPAGE_PMD_NR - 1;
			}

			if (!unfalloc || !PageUptodate(page)) {
				VM_BUG_ON_PAGE(PageTail(page), page);
				if (page_mapping(page) == mapping) {
					VM_BUG_ON_PAGE(PageWriteback(page), page);
					truncate_inode_page(mapping, page);
				} else {
					/* Page was replaced by swap: retry */
					unlock_page(page);
					index--;
					break;
				}
			}
			unlock_page(page);
		}
		pagevec_remove_exceptionals(&pvec); //	mm/swap.c
		pagevec_release(&pvec);
		index++;
	}

	spin_lock_irq(&info->lock);
	//info->swapped -= nr_swaps_freed;
	mbsfs_recalc_inode(inode);
	spin_unlock_irq(&info->lock);
}
void mbsfs_truncate_range(struct inode *inode, loff_t lstart, loff_t lend)
{
	mbsfs_undo_range(inode, lstart, lend, false);
	inode->i_ctime = inode->i_mtime = current_time(inode);
}
//EXPORT_SYMBOL_GPL(mbsfs_truncate_range);

#if 0
static int mbsfs_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = path->dentry->d_inode;
	struct mbsfs_inode_info *info = MBS_I(inode);

	//if (info->alloced - info->swapped != inode->i_mapping->nrpages) {
	if (info->alloced != inode->i_mapping->nrpages) {
		spin_lock_irq(&info->lock);
		mbsfs_recalc_inode(inode);
		spin_unlock_irq(&info->lock);
	}
	generic_fillattr(inode, stat);
	return 0;
}

static int mbsfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct mbsfs_inode_info *info = MBS_I(inode);
	//struct mbsfs_sb_info *sbinfo = MBS_SB(inode->i_sb);
	int error;

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		loff_t oldsize = inode->i_size;
		loff_t newsize = attr->ia_size;

		/* protected by i_mutex */
		if ((newsize < oldsize && (info->seals & F_SEAL_SHRINK)) ||
				(newsize > oldsize && (info->seals & F_SEAL_GROW)))
			return -EPERM;

		if (newsize != oldsize) {
			error = mbsFS_reacct_size(MBS_I(inode)->flags,
					oldsize, newsize);
			if (error)
				return error;
			i_size_write(inode, newsize);
			inode->i_ctime = inode->i_mtime = current_time(inode);
		}
		if (newsize <= oldsize) {
			loff_t holebegin = round_up(newsize, PAGE_SIZE);
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
						holebegin, 0, 1);
			if (info->alloced)
				mbsfs_truncate_range(inode,
						newsize, (loff_t)-1);
			/* unmap again to remove racily COWed private pages */
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
						holebegin, 0, 1);

			/*
			 * Part of the huge page can be beyond i_size: subject
			 * to shrink under memory pressure.
			 */
		}
	}

	setattr_copy(inode, attr);
	if (attr->ia_valid & ATTR_MODE)
		error = posix_acl_chmod(inode, inode->i_mode);
	return error;
}
#endif
static void mbsfs_evict_inode(struct inode *inode)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	//struct mbsfs_sb_info *sbinfo = MBS_SB(inode->i_sb);

	if (inode->i_mapping->a_ops == &mbsfs_aops) {
		mbsfs_unacct_size(info->flags, inode->i_size);
		inode->i_size = 0;
		mbsfs_truncate_range(inode, 0, (loff_t)-1);
#if 0
		if (!list_empty(&info->shrinklist)) {
			spin_lock(&sbinfo->shrinklist_lock);
			if (!list_empty(&info->shrinklist)) {
				list_del_init(&info->shrinklist);
				sbinfo->shrinklist_len--;
			}
			spin_unlock(&sbinfo->shrinklist_lock);
		}
		if (!list_empty(&info->swaplist)) {
			mutex_lock(&mbsFS_swaplist_mutex);
			list_del_init(&info->swaplist);
			mutex_unlock(&mbsFS_swaplist_mutex);
		}
#endif
	}

	//simple_xattrs_free(&info->xattrs);
	WARN_ON(inode->i_blocks);
	mbsfs_free_inode(inode->i_sb);
	clear_inode(inode);
}
#if 0

static unsigned long find_swap_entry(struct radix_tree_root *root, void *item)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned long found = -1;
	unsigned int checked = 0;

	rcu_read_lock();
	radix_tree_for_each_slot(slot, root, &iter, 0) {
		if (*slot == item) {
			found = iter.index;
			break;
		}
		checked++;
		if ((checked % 4096) != 0)
			continue;
		slot = radix_tree_iter_resume(slot, &iter);
		cond_resched_rcu();
	}

	rcu_read_unlock();
	return found;
} 
/*
 * If swap found in inode, free it and move page from swapcache to filecache.
 */

static int mbsFS_unuse_inode(struct mbsfs_inode_info *info,
		swp_entry_t swap, struct page **pagep)
{
	struct address_space *mapping = info->vfs_inode.i_mapping;
	void *radswap;
	pgoff_t index;
	gfp_t gfp;
	int error = 0;

	radswap = swp_to_radix_entry(swap);
	index = find_swap_entry(&mapping->page_tree, radswap);
	if (index == -1)
		return -EAGAIN;	/* tell mbsFS_unuse we found nothing */

	/*
	 * Move _head_ to start search for next from here.
	 * But be careful: mbsfs_evict_inode checks list_empty without taking
	 * mutex, and there's an instant in list_move_tail when info->swaplist
	 * would appear empty, if it were the only one on mbsFS_swaplist.
	 */
	if (mbsFS_swaplist.next != &info->swaplist)
		list_move_tail(&mbsFS_swaplist, &info->swaplist);

	gfp = mapping_gfp_mask(mapping);
	if (mbsFS_should_replace_page(*pagep, gfp)) {
		mutex_unlock(&mbsFS_swaplist_mutex);
		error = mbsFS_replace_page(pagep, gfp, info, index);
		mutex_lock(&mbsFS_swaplist_mutex);
		/*
		 * We needed to drop mutex to make that restrictive page
		 * allocation, but the inode might have been freed while we
		 * dropped it: although a racing mbsfs_evict_inode() cannot
		 * complete without emptying the radix_tree, our page lock
		 * on this swapcache page is not enough to prevent that -
		 * free_swap_and_cache() of our swap entry will only
		 * trylock_page(), removing swap from radix_tree whatever.
		 *
		 * We must not proceed to mbsfs_add_to_page_cache() if the
		 * inode has been freed, but of course we cannot rely on
		 * inode or mapping or info to check that.  However, we can
		 * safely check if our swap entry is still in use (and here
		 * it can't have got reused for another page): if it's still
		 * in use, then the inode cannot have been freed yet, and we
		 * can safely proceed (if it's no longer in use, that tells
		 * nothing about the inode, but we don't need to unuse swap).
		 */
		if (!page_swapcount(*pagep))
					    error = -ENOENT;
	}

	/*
	 * We rely on mbsFS_swaplist_mutex, not only to protect the swaplist,
	 * but also to hold up mbsfs_evict_inode(): so inode cannot be freed
	 * beneath us (pagelock doesn't help until the page is in pagecache).
	 */
	if (!error)
		   error = mbsfs_add_to_page_cache(*pagep, mapping, index,
				   radswap);
	if (error != -ENOMEM) {
		/*
		 * Truncation and eviction use free_swap_and_cache(), which
		 * only does trylock page: if we raced, best clean up here.
		 */
		delete_from_swap_cache(*pagep);
		set_page_dirty(*pagep);
		if (!error) {
			spin_lock_irq(&info->lock);
			info->swapped--;
			spin_unlock_irq(&info->lock);
			swap_free(swap);
		}
	}
	return error;
}

/*
 * Search through swapped inodes to find and replace swap by page.
 */

int mbsFS_unuse(swp_entry_t swap, struct page *page)
{
	struct list_head *this, *next;
	struct mbsfs_inode_info *info;
	struct mem_cgroup *memcg;
	int error = 0;

	/*
	 * There's a faint possibility that swap page was replaced before
	 * caller locked it: caller will come back later with the right page.
	 */
	if (unlikely(!PageSwapCache(page) || page_private(page) != swap.val))
		goto out;

	/*
	 * Charge page using GFP_KERNEL while we can wait, before taking
	 * the mbsFS_swaplist_mutex which might hold up mbsFS_writepage().
	 * Charged back to the user (not to caller) when swap account is used.
	 */
	error = mem_cgroup_try_charge(page, current->mm, GFP_KERNEL, &memcg,
			false);
	if (error)
		goto out;
	/* No radix_tree_preload: swap entry keeps a place for page in tree */
	error = -EAGAIN;

	mutex_lock(&mbsFS_swaplist_mutex);
	list_for_each_safe(this, next, &mbsFS_swaplist) {
		info = list_entry(this, struct mbsfs_inode_info, swaplist);
		if (info->swapped)
			error = mbsFS_unuse_inode(info, swap, &page);
		else
			list_del_init(&info->swaplist);
		cond_resched();
		if (error != -EAGAIN)
			break;
		/* found nothing in this: move on to search the next */
	}
	mutex_unlock(&mbsFS_swaplist_mutex);

	if (error) {
		if (error != -ENOMEM)
			error = 0;
		mem_cgroup_cancel_charge(page, memcg, false);
	} else
		mem_cgroup_commit_charge(page, memcg, true, false);
out:
	unlock_page(page);
	put_page(page);
	return error;
}

/*
 * Move the page from the page cache to the swap cache.
 */

static int mbsFS_writepage(struct page *page, struct writeback_control *wbc)
{
	struct mbsfs_inode_info *info;
	struct address_space *mapping;
	struct inode *inode;
	swp_entry_t swap;
	pgoff_t index;

	VM_BUG_ON_PAGE(PageCompound(page), page);
	BUG_ON(!PageLocked(page));
	mapping = page->mapping;
	index = page->index;
	inode = mapping->host;
	info = MBS_I(inode);
	if (info->flags & VM_LOCKED)
		goto redirty;
	if (!total_swap_pages)
		goto redirty;

	/*
	 * Our capabilities prevent regular writeback or sync from ever calling
	 * mbsFS_writepage; but a stacking filesystem might use ->writepage of
	 * its underlying filesystem, in which case mbsfs should write out to
	 * swap only in response to memory pressure, and not for the writeback
	 * threads or sync.
	 */
	if (!wbc->for_reclaim) {
		WARN_ON_ONCE(1);	/* Still happens? Tell us about it! */
		goto redirty;
	}

	/*
	 * This is somewhat ridiculous, but without plumbing a SWAP_MAP_FALLOC
	 * value into swapfile.c, the only way we can correctly account for a
	 * fallocated page arriving here is now to initialize it and write it.
	 *
	 * That's okay for a page already fallocated earlier, but if we have
	 * not yet completed the fallocation, then (a) we want to keep track
	 * of this page in case we have to undo it, and (b) it may not be a
	 * good idea to continue anyway, once we're pushing into swap.  So
	 * reactivate the page, and let mbsfs_fallocate() quit when too many.
	 */
	if (!PageUptodate(page)) {
		if (inode->i_private) {
			struct mbsFS_falloc *mbsFS_falloc;
			spin_lock(&inode->i_lock);
			mbsFS_falloc = inode->i_private;
			if (mbsFS_falloc &&
					!mbsFS_falloc->waitq &&
					index >= mbsFS_falloc->start &&
					index < mbsFS_falloc->next)
				mbsFS_falloc->nr_unswapped++;
			else
				mbsFS_falloc = NULL;
			spin_unlock(&inode->i_lock);
			if (mbsFS_falloc)
				goto redirty;
		}
		clear_highpage(page);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}

	swap = get_swap_page(page);
	if (!swap.val)
		goto redirty;
	if (mem_cgroup_try_charge_swap(page, swap))
		goto free_swap;
	/*
	 * Add inode to mbsFS_unuse()'s list of swapped-out inodes,
	 * if it's not already there.  Do it now before the page is
	 * moved to swap cache, when its pagelock no longer protects
	 * the inode from eviction.  But don't unlock the mutex until
	 * we've incremented swapped, because mbsFS_unuse_inode() will
	 * prune a !swapped inode from the swaplist under this mutex.
	 */
	mutex_lock(&mbsFS_swaplist_mutex);
	if (list_empty(&info->swaplist))
		list_add_tail(&info->swaplist, &mbsFS_swaplist);

	if (add_to_swap_cache(page, swap, GFP_ATOMIC) == 0) {
		spin_lock_irq(&info->lock);
		mbsfs_recalc_inode(inode);
		info->swapped++;
		spin_unlock_irq(&info->lock);

		swap_mbsfs_alloc(swap);
		mbsFS_delete_from_page_cache(page, swp_to_radix_entry(swap));

		mutex_unlock(&mbsFS_swaplist_mutex);
		BUG_ON(page_mapped(page));
		swap_writepage(page, wbc);
		return 0;
	}

	mutex_unlock(&mbsFS_swaplist_mutex);
free_swap:
	put_swap_page(page, swap);
redirty:
	set_page_dirty(page);
	if (wbc->for_reclaim)
		return AOP_WRITEPAGE_ACTIVATE;	/* Return with page locked */
	unlock_page(page);
	return 0;
}
#endif
static void mbsfs_show_mpol(struct seq_file *seq, struct mempolicy *mpol)
{
	char buffer[64];

	if (!mpol || mpol->mode == MPOL_DEFAULT)
		return;		/* show nothing */

	mpol_to_str_pram(buffer, sizeof(buffer), mpol);

	seq_printf(seq, ",flag=%s", buffer);
}


static struct mempolicy *mbsfs_get_sbmpol(struct mbsfs_sb_info *sbinfo)
{
	struct mempolicy *mpol = NULL;
	if (sbinfo->mpol) {
		spin_lock(&sbinfo->stat_lock);	/* prevent replace/use races */
		mpol = sbinfo->mpol;
		mpol_get(mpol);
		spin_unlock(&sbinfo->stat_lock);
	}
	return mpol;
}

static void mbsfs_pseudo_vma_init(struct vm_area_struct *vma,
		struct mbsfs_inode_info *info, pgoff_t index)
{
	/* Create a pseudo vma that just contains the policy */
	vma->vm_start = 0;
	/* Bias interleave by inode number to distribute better across nodes */
	vma->vm_pgoff = index + info->vfs_inode.i_ino;
	vma->vm_ops = NULL;
	vma->vm_policy = mpol_mbsfs_policy_lookup(&info->policy, index);
}

static void mbsfs_pseudo_vma_destroy(struct vm_area_struct *vma)
{
	/* Drop reference taken by mpol_mbsfs_policy_lookup() */
	mpol_cond_put_pram(vma->vm_policy);
}
#if 0
static struct page *mbsFS_swapin(swp_entry_t swap, gfp_t gfp,
		struct mbsfs_inode_info *info, pgoff_t index)
{
	struct vm_area_struct pvma;
	struct page *page;

	mbsfs_pseudo_vma_init(&pvma, info, index);
	page = swapin_readahead(swap, gfp, &pvma, 0);
	mbsfs_pseudo_vma_destroy(&pvma);

	return page;
}
#endif
static struct page *mbsfs_alloc_hugepage(gfp_t gfp,
		struct mbsfs_inode_info *info, pgoff_t index)
{
	struct vm_area_struct pvma;
	struct inode *inode = &info->vfs_inode;
	struct address_space *mapping = inode->i_mapping;
	pgoff_t idx, hindex;
	void __rcu **results;
	struct page *page;

	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGE_PAGECACHE))
	return NULL;

	hindex = round_down(index, HPAGE_PMD_NR);
	rcu_read_lock();
	if (radix_tree_gang_lookup_slot(&mapping->page_tree, &results, &idx,
				hindex, 1) && idx < hindex + HPAGE_PMD_NR) {
		rcu_read_unlock();
		return NULL;
	}
	rcu_read_unlock();

	mbsfs_pseudo_vma_init(&pvma, info, hindex);
	//page = alloc_pages_vma(gfp | __GFP_COMP | __GFP_NORETRY | __GFP_NOWARN,
	//		HPAGE_PMD_ORDER, &pvma, 0, numa_node_id(), true);
	page = alloc_prams_vma(gfp | __GFP_COMP | __GFP_NORETRY | __GFP_NOWARN,
			HPAGE_PMD_ORDER, &pvma, 0, numa_node_id(), true);
	mbsfs_pseudo_vma_destroy(&pvma);
	//if (page)
	//prep_transhuge_page(page);
	return page;
}
#if 0
#endif
static struct page *mbsfs_alloc_page(gfp_t gfp,
		struct mbsfs_inode_info *info, pgoff_t index)
{
	struct vm_area_struct pvma;
	struct page *page;

	mbsfs_pseudo_vma_init(&pvma, info, index);
	gfp |= GFP_PRAM;
	//page = alloc_pram_vma(gfp, &pvma, 0); 
	//page = alloc_prams_vma(gfp, 0, &pvma, 0, numa_node_id(), false);
	//page = alloc_prams_vma(gfp, 0, &pvma, ORDERS, numa_node_id(), false);
	//page = alloc_prams_vma2(gfp, 0, &pvma, ORDERS, numa_node_id(), LOCAL);
	page = alloc_prams_vma_pram_policy(gfp, 0, &pvma, ORDERS, numa_node_id(), false);
	//page = alloc_prams_vma(gfp, 0, &pvma, 0, nd, false);
	//page = alloc_page_vma(gfp, &pvma, 0);
	mbsfs_pseudo_vma_destroy(&pvma);

	return page;
}

static struct page *mbsfs_alloc_and_acct_page(gfp_t gfp,
		struct inode *inode,
		pgoff_t index, bool huge)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	struct page *page;
	int nr;
	int err = -ENOSPC;

	//if (1)
	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGE_PAGECACHE))
		huge = false;
	nr = huge ? HPAGE_PMD_NR : 1;
#if 1
	if (!mbsFS_inode_acct_block(inode, nr))
		goto failed;

	if (huge)
		page = mbsfs_alloc_hugepage(gfp, info, index);
	else
#endif
		page = mbsfs_alloc_page(gfp, info, index);
	if (page) {
		//__SetPageLocked(page);
		//__SetPageSwapBacked(page);
		return page;
	}

	err = -ENOMEM;
	err = -ENOSPC;
	mbsfs_inode_unacct_blocks(inode, nr);
failed:
	return ERR_PTR(err);
}
#if 0
/*
 * When a page is moved from swapcache to mbsFS filecache (either by the
 * usual swapin of mbsfs_getpage_gfp(), or by the less common swapoff of
 * mbsFS_unuse_inode()), it may have been read in earlier from swap, in
 * ignorance of the mapping it belongs to.  If that mapping has special
 * constraints (like the gma500 GEM driver, which requires RAM below 4GB),
 * we may need to copy to a suitable page before moving to filecache.
 *
 * In a future release, this may well be extended to respect cpuset and
 * NUSA prampolicy, and applied also to anonymous pages in do_swap_page();
 * but for now it is a simple matter of zone.
 */
static bool mbsFS_should_replace_page(struct page *page, gfp_t gfp)
{
	return page_zonenum(page) > gfp_zone(gfp);
}
static int mbsFS_replace_page(struct page **pagep, gfp_t gfp,
		struct mbsfs_inode_info *info, pgoff_t index)
{
	struct page *oldpage, *newpage;
	struct address_space *swap_mapping;
	pgoff_t swap_index;
	int error;

	oldpage = *pagep;
	swap_index = page_private(oldpage);
	swap_mapping = page_mapping(oldpage);

	/*
	 * We have arrived here because our zones are constrained, so don't
	 * limit chance of success by further cpuset and node constraints.
	 */
	gfp &= ~GFP_CONSTRAINT_MASK;
	newpage = mbsfs_alloc_page(gfp, info, index, numa_node_id());
	if (!newpage)
		return -ENOMEM;

	get_page(newpage);
	copy_highpage(newpage, oldpage);
	flush_dcache_page(newpage);

	__SetPageLocked(newpage);
	__SetPageSwapBacked(newpage);
	SetPageUptodate(newpage);
	set_page_private(newpage, swap_index);
	SetPageSwapCache(newpage);

	/*
	 * Our caller will very soon move newpage out of swapcache, but it's
	 * a nice clean interface for us to replace oldpage by newpage there.
	 */
	spin_lock_irq(&swap_mapping->tree_lock);
	error = mbsfs_radix_tree_replace(swap_mapping, swap_index, oldpage,
			newpage);
	if (!error) {
		__inc_node_page_state(newpage, NR_FILE_PAGES);
		__dec_node_page_state(oldpage, NR_FILE_PAGES);
	}
	spin_unlock_irq(&swap_mapping->tree_lock);

	if (unlikely(error)) {
		/*
		 * Is this possible?  I think not, now that our callers check
		 * both PageSwapCache and page_private after getting page lock;
		 * but be defensive.  Reverse old to newpage for clear and free.
		 */
		oldpage = newpage;
	} else {
		mem_cgroup_migrate(oldpage, newpage);
		lru_cache_add_anon(newpage);	//	mm/swap.c
		*pagep = newpage;
	}

	ClearPageSwapCache(oldpage);
	set_page_private(oldpage, 0);

	unlock_page(oldpage);
	put_page(oldpage);
	put_page(oldpage);
	return error;
}
#endif
/*
 * mbsfs_getpage_gfp - find page in cache, or or allocate
 *
 * If we allocate a new one we do not mark it dirty. That's up to the
 * vm. If we swap it in we mark it dirty since we also free the swap
 * entry since a page cannot live in both the swap and page cache.
 *
 * fault_mm and fault_type are only supplied by mbsfs_fault:
 * otherwise they are NULL.
 */
static int mbsfs_getpage_gfp(struct inode *inode, pgoff_t index,
		struct page **pagep, enum mbs_type mbstype, gfp_t gfp,
		struct vm_area_struct *vma, struct vm_fault *vmf, int *fault_type)
{
	struct address_space *mapping = inode->i_mapping;
	struct mbsfs_inode_info *info = MBS_I(inode);
	struct mbsfs_sb_info *sbinfo;
	struct mm_struct *charge_mm;
	struct mem_cgroup *memcg;
	struct page *page;
	swp_entry_t swap;
	enum mbs_type mbstype_huge = mbstype;
	pgoff_t hindex = index;
	int error;
	int once = 0;
	int alloced = 0;

	if (index > (MAX_LFS_FILESIZE >> PAGE_SHIFT))
		return -EFBIG; /*File too large*/
	if (mbstype == MBS_NOHUGE || mbstype == MBS_HUGE)
		mbstype = MBS_CACHE;
repeat:
	swap.val = 0;
	//page = find_lock_entry(mapping, index);	//complex style
	page = find_get_entry(mapping, index);		//simple style
	
	if (radix_tree_exceptional_entry(page)) {
	   /* swap = radix_to_swp_entry(page); */
	   page = NULL;
//	   goto alloc_nohuge;//2019.01.02 19:25
	}
	   
	if (mbstype <= MBS_CACHE &&
			((loff_t)index << PAGE_SHIFT) >= i_size_read(inode)) {
		error = -EINVAL;
		goto unlock;
	}

	if (page && mbstype == MBS_WRITE)
		mark_page_accessed(page);

	/* fallocated page? */
	if (page && !PageUptodate(page)) {
		if (mbstype != MBS_READ)
			goto clear;
		unlock_page(page);
		put_page(page);
		page = NULL;
	}
	if (page || (mbstype == MBS_READ && !swap.val)) {
		*pagep = page;
		return 0;
	}

	/*
	 * Fast cache lookup did not find it:
	 * bring it back from swap or allocate.
	 */
	sbinfo = MBS_SB(inode->i_sb);
	charge_mm = vma ? vma->vm_mm : current->mm;
#if 0
	if (swap.val) {
		/* Look it up and read it in.. */
		page = lookup_swap_cache(swap, NULL, 0);
		if (!page) {
			/* Or update major stats only when swapin succeeds?? */
			if (fault_type) {
				*fault_type |= VM_FAULT_MAJOR;
				count_vm_event(PGMAJFAULT);
				count_memcg_event_mm(charge_mm, PGMAJFAULT);
			}
			/* Here we actually start the io */
			page = mbsFS_swapin(swap, gfp, info, index);
			if (!page) {
				error = -ENOMEM;
				goto failed;
			}
		}

		/* We have to do this with page locked to prevent races */
		lock_page(page);
		if (!PageSwapCache(page) || page_private(page) != swap.val ||
				!mbsFS_confirm_swap(mapping, index, swap)) {
			error = -EEXIST;	/* try again */
			goto unlock;
		}
		if (!PageUptodate(page)) {
			error = -EIO;
			goto failed;
		}
		wait_on_page_writeback(page);

		if (mbsFS_should_replace_page(page, gfp)) {
			error = mbsFS_replace_page(&page, gfp, info, index);
			if (error)
				goto failed;
		}

		error = mem_cgroup_try_charge(page, charge_mm, gfp, &memcg,
				false);
		if (!error) {
			error = mbsfs_add_to_page_cache(page, mapping, index,
					swp_to_radix_entry(swap));
			/*
			 * We already confirmed swap under page lock, and make
			 * no memory allocation here, so usually no possibility
			 * of error; but free_swap_and_cache() only trylocks a
			 * page, so it is just possible that the entry has been
			 * truncated or holepunched since swap was confirmed.
			 * mbsfs_undo_range() will have done some of the
			 * unaccounting, now delete_from_swap_cache() will do
			 * the rest.
			 * Reset swap.val? No, leave it so "failed" goes back to
			 * "repeat": reading a hole and writing should succeed.
			 */
			if (error) {
				mem_cgroup_cancel_charge(page, memcg, false);
				delete_from_swap_cache(page);
			}
		}
		if (error)
			goto failed;

		mem_cgroup_commit_charge(page, memcg, true, false);

		spin_lock_irq(&info->lock);
		info->swapped--;
		mbsfs_recalc_inode(inode);
		spin_unlock_irq(&info->lock);

		if (mbstype == MBS_WRITE)
			mark_page_accessed(page);

		delete_from_swap_cache(page);
		set_page_dirty(page);
		swap_free(swap);

	} else
#endif
	{
		if (vma && userfaultfd_missing(vma)) {
			*fault_type = handle_userfault(vmf, VM_UFFD_MISSING);
			return 0;
		}

		/* mbsfs_symlink() */
		if (mapping->a_ops != &mbsfs_aops)
			goto alloc_nohuge;
		if (mbsFS_huge == MBS_HUGE_DENY || mbstype_huge == MBS_NOHUGE)
			goto alloc_nohuge;
		if (mbsFS_huge == MBS_HUGE_FORCE)
			goto alloc_huge;
		switch (sbinfo->huge) {
			loff_t i_size;
			pgoff_t off;
		case MBS_HUGE_NEVER:
			goto alloc_nohuge;
		case MBS_HUGE_WITHIN_SIZE:
			off = round_up(index, HPAGE_PMD_NR);
			i_size = round_up(i_size_read(inode), PAGE_SIZE);
			if (i_size >= HPAGE_PMD_SIZE &&
					i_size >> PAGE_SHIFT >= off)
				goto alloc_huge;
			/* fallthrough */
		case MBS_HUGE_ADVISE:
			if (mbstype_huge == MBS_HUGE)
				goto alloc_huge;
			/* TODO: implement fadvise() hints */
			goto alloc_nohuge;
		}

alloc_huge:
		page = mbsfs_alloc_and_acct_page(gfp, inode, index, true);
		if (IS_ERR(page)) {
alloc_nohuge:		page = mbsfs_alloc_and_acct_page(gfp, inode,
					index, false);
		}
#if 1 //2019.01.02 19:26 enable huge
		if (IS_ERR(page)) {
			int retry = 5;
			error = PTR_ERR(page);
			page = NULL;
			if (error != -ENOSPC)
				goto failed;
			/*
			 * Try to reclaim some spece by splitting a huge page
			 * beyond i_size on the filesystem.
			 */
			while (retry--) {
				int ret;
				ret = mbsfs_unused_huge_shrink(sbinfo, NULL, 1);
				if (ret == SHRINK_STOP)
					break;
				if (ret)
					goto alloc_nohuge;
			}
			goto failed;
		}
		if (PageTransHuge(page))
			hindex = round_down(index, HPAGE_PMD_NR);
		else
#endif
			hindex = index;

		if (mbstype == MBS_WRITE)
			__SetPageReferenced(page);
#if 1
		error = mem_cgroup_try_charge(page, charge_mm, gfp, &memcg,
				PageTransHuge(page));
		if (error)
			goto unacct;
#endif
		error = radix_tree_maybe_preload_order(gfp & GFP_RECLAIM_MASK,
				compound_order(page));
		if (!error) {
			error = mbsfs_add_to_page_cache(page, mapping, hindex,
					NULL);
			radix_tree_preload_end();
		}
		if (error) {
			mem_cgroup_cancel_charge(page, memcg,
					PageTransHuge(page));
			goto unacct;
		}
#if 1
		mem_cgroup_commit_charge(page, memcg, false,
				PageTransHuge(page));
#endif
		lru_cache_add_anon(page);	//	mm/swap.c

		spin_lock_irq(&info->lock);
		info->alloced += 1 << compound_order(page);
		inode->i_blocks += BLOCKS_PER_PAGE << compound_order(page);
		mbsfs_recalc_inode(inode);
		spin_unlock_irq(&info->lock);
		alloced = true;
#if 0
		if (PageTransHuge(page) &&
				DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE) <
				hindex + HPAGE_PMD_NR - 1) {
			/*
			 * Part of the huge page is beyond i_size: subject
			 * to shrink under memory pressure.
			 */
			spin_lock(&sbinfo->shrinklist_lock);
			/*
			 * _careful to defend against unlocked access to
			 * ->shrink_list in mbsFS_unused_huge_shrink()
			 */
			if (list_empty_careful(&info->shrinklist)) {
				list_add_tail(&info->shrinklist,
						&sbinfo->shrinklist);
				sbinfo->shrinklist_len++;
			}
			spin_unlock(&sbinfo->shrinklist_lock);
		}
#endif
		/*
		 * Let MBS_FALLOC use the MBS_WRITE optimization on a new page.
		 */
		if (mbstype == MBS_FALLOC)
			mbstype = MBS_WRITE;
clear:
		/*
		 * Let MBS_WRITE caller clear ends if write does not fill page;
		 * but MBS_FALLOC on a page fallocated earlier must initialize
		 * it now, lest undo on failure cancel our earlier guarantee.
		 */
		if (mbstype != MBS_WRITE && !PageUptodate(page)) {
			struct page *head = compound_head(page);
			int i;

			for (i = 0; i < (1 << compound_order(head)); i++) {
				clear_highpage(head + i);
				flush_dcache_page(head + i);
			}
			SetPageUptodate(head);
		}
	}

	/* Perhaps the file has been truncated since we checked */
	if (mbstype <= MBS_CACHE &&
			((loff_t)index << PAGE_SHIFT) >= i_size_read(inode)) {
		if (alloced) {
			ClearPageDirty(page);
			delete_from_page_cache(page);
			spin_lock_irq(&info->lock);
			mbsfs_recalc_inode(inode);
			spin_unlock_irq(&info->lock);
		}
		error = -EINVAL;
		goto unlock;
	}
	*pagep = page + index - hindex;
	return 0;

	/*
	 * Error recovery.
	 */
unacct:
	mbsfs_inode_unacct_blocks(inode, 1 << compound_order(page));
#if 1
	if (PageTransHuge(page)) {
		unlock_page(page);
		put_page(page);
		goto alloc_nohuge;
	}
failed:
//	if (swap.val && !mbsFS_confirm_swap(mapping, index, swap))
//		error = -EEXIST;
#endif
unlock:
	if (page) {
		unlock_page(page);
		put_page(page);
	}
	if (error == -ENOSPC && !once++) {
		spin_lock_irq(&info->lock);
		mbsfs_recalc_inode(inode);
		spin_unlock_irq(&info->lock);
		goto repeat;
	}
	if (error == -EEXIST)	/* from above or from radix_tree_insert */
		goto repeat;
	return error;
}

/*
 * This is like autoremove_wake_function, but it removes the wait queue
 * entry unconditionally - even if something else had already woken the
 * target.
 */
static int synchronous_wake_function(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	int ret = default_wake_function(wait, mode, sync, key);
	list_del_init(&wait->entry);
	return ret;
}

static int mbsfs_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	gfp_t gfp = mapping_gfp_mask(inode->i_mapping);
	enum mbs_type mbstype;
	int error;
	int ret = VM_FAULT_LOCKED;

	/*
	 * Trinity finds that probing a hole which mbsfs is punching can
	 * prevent the hole-punch from ever completing: which in turn
	 * locks writers out with its hold on i_mutex.  So refrain from
	 * faulting pages into the hole while it's being punched.  Although
	 * mbsfs_undo_range() does remove the additions, it may be unable to
	 * keep up, as each new page needs its own unmap_mapping_range() call,
	 * and the i_mmap tree grows ever slower to scan if new vmas are added.
	 *
	 * It does not matter if we sometimes reach this check just before the
	 * hole-punch begins, so that one fault then races with the punch:
	 * we just need to make racing faults a rare case.
	 *
	 * The implementation below would be much simpler if we just used a
	 * standard mutex or completion: but we cannot take i_mutex in fault,
	 * and bloating every mbsFS inode for this unlikely case would be sad.
	 */
	if (unlikely(inode->i_private)) {
		struct mbsfs_falloc *mbsFS_falloc;

		spin_lock(&inode->i_lock);
		mbsFS_falloc = inode->i_private;
		if (mbsFS_falloc &&
				mbsFS_falloc->waitq &&
				vmf->pgoff >= mbsFS_falloc->start &&
				vmf->pgoff < mbsFS_falloc->next) {
			wait_queue_head_t *mbsFS_falloc_waitq;
			DEFINE_WAIT_FUNC(mbsFS_fault_wait, synchronous_wake_function);

			ret = VM_FAULT_NOPAGE;
			if ((vmf->flags & FAULT_FLAG_ALLOW_RETRY) &&
					!(vmf->flags & FAULT_FLAG_RETRY_NOWAIT)) {
				/* It's polite to up mmap_sem if we can */
				up_read(&vma->vm_mm->mmap_sem);
				ret = VM_FAULT_RETRY;
			}

			mbsFS_falloc_waitq = mbsFS_falloc->waitq;
			prepare_to_wait(mbsFS_falloc_waitq, &mbsFS_fault_wait,
					TASK_UNINTERRUPTIBLE);
			spin_unlock(&inode->i_lock);
			schedule();

			/*
			 * mbsFS_falloc_waitq points into the mbsfs_fallocate()
			 * stack of the hole-punching task: mbsFS_falloc_waitq
			 * is usually invalid by the time we reach here, but
			 * finish_wait() does not dereference it in that case;
			 * though i_lock needed lest racing with wake_up_all().
			 */
			spin_lock(&inode->i_lock);
			finish_wait(mbsFS_falloc_waitq, &mbsFS_fault_wait);
			spin_unlock(&inode->i_lock);
			return ret;
		}
		spin_unlock(&inode->i_lock);
	}

	mbstype = MBS_CACHE;

	if ((vma->vm_flags & VM_NOHUGEPAGE) ||
			test_bit(MMF_DISABLE_THP, &vma->vm_mm->flags))
		mbstype = MBS_NOHUGE;
	else if (vma->vm_flags & VM_HUGEPAGE)
		mbstype = MBS_HUGE;

	error = mbsfs_getpage_gfp(inode, vmf->pgoff, &vmf->page, mbstype,
			gfp, vma, vmf, &ret);
	if (error)
		return ((error == -ENOMEM) ? VM_FAULT_OOM : VM_FAULT_SIGBUS);
	return ret;
}
#if 0
#endif
unsigned long mbsfs_get_unmapped_area(struct file *file,
		unsigned long uaddr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	unsigned long (*get_area)(struct file *,
			unsigned long, unsigned long, unsigned long, unsigned long);
	unsigned long addr;
	unsigned long offset;
	unsigned long inflated_len;
	unsigned long inflated_addr;
	unsigned long inflated_offset;

	if (len > TASK_SIZE)
		return -ENOMEM;

	get_area = current->mm->get_unmapped_area;
	addr = get_area(file, uaddr, len, pgoff, flags);

	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGE_PAGECACHE))//20190102 20:12
	return addr;
	if (IS_ERR_VALUE(addr))
		return addr;
	if (addr & ~PAGE_MASK)
		return addr;
	if (addr > TASK_SIZE - len)
		return addr;

	if (mbsFS_huge == MBS_HUGE_DENY)
		return addr;
	if (len < HPAGE_PMD_SIZE)
		return addr;
	if (flags & MAP_FIXED)
		return addr;
	/*
	 * Our priority is to support MAP_SHARED mapped hugely;
	 * and support MAP_PRIVATE mapped hugely too, until it is COWed.
	 * But if caller specified an address hint, respect that as before.
	 */
	if (uaddr)
		return addr;

	if (mbsFS_huge != MBS_HUGE_FORCE) {
		struct super_block *sb;

		if (file) {
			VM_BUG_ON(file->f_op != &mbsfs_file_operations);
			sb = file_inode(file)->i_sb;
		} else {
			/*
			 * Called directly from mm/mmap.c, or drivers/char/mem.c
			 * for "/dev/zero", to create a MBS anonymous object.
			 */
			if (IS_ERR(mbsfs_mnt))
				return addr;
			sb = mbsfs_mnt->mnt_sb;
		}
		if (MBS_SB(sb)->huge == MBS_HUGE_NEVER)
			return addr;
	}

	offset = (pgoff << PAGE_SHIFT) & (HPAGE_PMD_SIZE-1);
	if (offset && offset + len < 2 * HPAGE_PMD_SIZE)
		return addr;
	if ((addr & (HPAGE_PMD_SIZE-1)) == offset)
		return addr;

	inflated_len = len + HPAGE_PMD_SIZE - PAGE_SIZE;
	if (inflated_len > TASK_SIZE)
		return addr;
	if (inflated_len < len)
		return addr;

	inflated_addr = get_area(NULL, 0, inflated_len, 0, flags);
	if (IS_ERR_VALUE(inflated_addr))
		return addr;
	if (inflated_addr & ~PAGE_MASK)
		return addr;

	inflated_offset = inflated_addr & (HPAGE_PMD_SIZE-1);
	inflated_addr += offset - inflated_offset;
	if (inflated_offset > offset)
		inflated_addr += HPAGE_PMD_SIZE;

	if (inflated_addr > TASK_SIZE - len)
		return addr;
	return inflated_addr;
}

#ifdef CONFIG_NUMA
static int mbsfs_set_policy(struct vm_area_struct *vma, struct mempolicy *mpol)
{
	struct inode *inode = file_inode(vma->vm_file);
	return mpol_set_mbsfs_policy(&MBS_I(inode)->policy, vma, mpol);
}

static struct mempolicy *mbsfs_get_policy(struct vm_area_struct *vma,
		unsigned long addr)
{
	struct inode *inode = file_inode(vma->vm_file);
	pgoff_t index;

	index = ((addr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
	return mpol_mbsfs_policy_lookup(&MBS_I(inode)->policy, index);
}
#if 0
int mbsFS_lock(struct file *file, int lock, struct user_struct *user)
{
	struct inode *inode = file_inode(file);
	struct mbsfs_inode_info *info = MBS_I(inode);
	int retval = -ENOMEM;

	spin_lock_irq(&info->lock);
	if (lock && !(info->flags & VM_LOCKED)) {
		if (!user_pram_lock(inode->i_size, user))
			goto out_nomem;
		info->flags |= VM_LOCKED;
		mapping_set_unevictable(file->f_mapping);
	}
	if (!lock && (info->flags & VM_LOCKED) && user) {
		user_pram_unlock(inode->i_size, user);
		info->flags &= ~VM_LOCKED;
		mapping_clear_unevictable(file->f_mapping);
	}
	retval = 0;

out_nomem:
	spin_unlock_irq(&info->lock);
	return retval;
}
#endif
static int mbsfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &mbsfs_vm_ops;
	return 0;
}
#endif
static struct inode *mbsfs_get_inode(struct super_block *sb, const struct inode *dir,
		umode_t mode, dev_t dev, unsigned long flags)
{
	struct inode * inode = new_inode(sb);
	struct mbsfs_inode_info *info;
	struct mbsfs_sb_info *sbinfo = MBS_SB(sb);

	if (mbsfs_reserve_inode(sb)) //rNO
		return NULL;

	if (inode) {
		inode->i_ino = get_next_ino();
		inode_init_owner(inode, dir, mode);
		inode->i_blocks = 0;
		inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_generation = get_seconds();//rNO
		info = MBS_I(inode);
		memset(info, 0, (char *)inode - (char *)info);
		spin_lock_init(&info->lock);			//rNO
		info->flags = flags; // & VM_NONE;		//rNO
		//info->seals = F_SEAL_SEAL;			//rNO
		////INIT_LIST_HEAD(&info->shrinklist);		//rNO
		////INIT_LIST_HEAD(&info->swaplist);		//rNO
		//simple_xattrs_init(&info->xattrs);		//rNO
		//cache_no_acl(inode);				//rNO
		//inode->i_mapping->a_ops = &mbsfs_aops;	
		//mapping_set_gfp_mask(inode->i_mapping, GFP_PRAM);//tNO
		mapping_set_unevictable(inode->i_mapping);

		switch (mode & S_IFMT) {
			default:
				inode->i_op = &mbsfs_special_inode_operations;
				init_special_inode(inode, mode, dev);
				break;
			case S_IFREG:
				inode->i_mapping->a_ops = &mbsfs_aops;
				inode->i_op = &mbsfs_inode_operations;
				inode->i_fop = &mbsfs_file_operations;
				mpol_mbsfs_policy_init(&info->policy,
						mbsfs_get_sbmpol(sbinfo));
				break;
			case S_IFDIR:
				inc_nlink(inode); //rNO
				/* Some things misbehave if size == 0 on a directory */
				inode->i_size = 2 * BOGO_DIRENT_SIZE;
				inode->i_op = &mbsfs_dir_inode_operations;
				inode->i_fop = &simple_dir_operations;
				break;
			case S_IFLNK:
				inode->i_op = &page_symlink_inode_operations;
				inode_nohighmem(inode);
				mpol_mbsfs_policy_init(&info->policy, NULL);
				break;
		}
	} else {
		mbsfs_free_inode(sb);
		pr_err("inode allocation failed\n");
	}
	return inode;
}

#if 0
bool mbsFS_mapping(struct address_space *mapping)
{
	return mapping->a_ops == &mbsfs_aops;
}

static int mbsFS_mfill_atomic_pte(struct mm_struct *dst_mm,
		pmd_t *dst_pmd,
		struct vm_area_struct *dst_vma,
		unsigned long dst_addr,
		unsigned long src_addr,
		bool zeropage,
		struct page **pagep)
{
	struct inode *inode = file_inode(dst_vma->vm_file);
	struct mbsfs_inode_info *info = MBS_I(inode);
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfp = mapping_gfp_mask(mapping);
	pgoff_t pgoff = linear_page_index(dst_vma, dst_addr);
	struct mem_cgroup *memcg;
	spinlock_t *ptl;
	void *page_kaddr;
	struct page *page;
	pte_t _dst_pte, *dst_pte;
	int ret;

	ret = -ENOMEM;
	if (!mbsFS_inode_acct_block(inode, 1))
		goto out;

	if (!*pagep) {
		page = mbsfs_alloc_page(gfp, info, pgoff, numa_node_id());
		if (!page)
			goto out_unacct_blocks;

		if (!zeropage) {	/* mcopy_atomic */
			page_kaddr = kmap_atomic(page);
			ret = copy_from_user(page_kaddr,
					(const void __user *)src_addr,
					PAGE_SIZE);
			kunmap_atomic(page_kaddr);

			/* fallback to copy_from_user outside mmap_sem */
			if (unlikely(ret)) {
				*pagep = page;
				mbsfs_inode_unacct_blocks(inode, 1);
				/* don't free the page */
				return -EFAULT;
			}
		} else {		/* mfill_zeropage_atomic */
			clear_highpage(page);
		}
	} else {
		page = *pagep;
		*pagep = NULL;
	}

	VM_BUG_ON(PageLocked(page) || PageSwapBacked(page));
	__SetPageLocked(page);
	__SetPageSwapBacked(page);
	__SetPageUptodate(page);

	ret = mem_cgroup_try_charge(page, dst_mm, gfp, &memcg, false);
	if (ret)
		goto out_release;

	ret = radix_tree_maybe_preload(gfp & GFP_RECLAIM_MASK);
	if (!ret) {
		ret = mbsfs_add_to_page_cache(page, mapping, pgoff, NULL);
		radix_tree_preload_end();
	}
	if (ret)
		goto out_release_uncharge;

	mem_cgroup_commit_charge(page, memcg, false, false);

	_dst_pte = mk_pte(page, dst_vma->vm_page_prot);
	if (dst_vma->vm_flags & VM_WRITE)
		_dst_pte = pte_mkwrite(pte_mkdirty(_dst_pte));

	ret = -EEXIST;
	dst_pte = pte_offset_map_lock(dst_mm, dst_pmd, dst_addr, &ptl);
	if (!pte_none(*dst_pte))
		goto out_release_uncharge_unlock;

	lru_cache_add_anon(page);	//	mm/swap.c

	spin_lock(&info->lock);
	info->alloced++;
	inode->i_blocks += BLOCKS_PER_PAGE;
	mbsfs_recalc_inode(inode);
	spin_unlock(&info->lock);

	inc_mm_counter(dst_mm, mm_counter_file(page));
	page_add_file_rmap(page, false);
	set_pte_at(dst_mm, dst_addr, dst_pte, _dst_pte);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(dst_vma, dst_addr, dst_pte);
	unlock_page(page);
	pte_unmap_unlock(dst_pte, ptl);
	ret = 0;
out:
	return ret;
out_release_uncharge_unlock:
	pte_unmap_unlock(dst_pte, ptl);
out_release_uncharge:
	mem_cgroup_cancel_charge(page, memcg, false);
out_release:
	unlock_page(page);
	put_page(page);
out_unacct_blocks:
	mbsfs_inode_unacct_blocks(inode, 1);
	goto out;
}

int mbsFS_mcopy_atomic_pte(struct mm_struct *dst_mm,
		pmd_t *dst_pmd,
		struct vm_area_struct *dst_vma,
		unsigned long dst_addr,
		unsigned long src_addr,
		struct page **pagep)
{
	return mbsFS_mfill_atomic_pte(dst_mm, dst_pmd, dst_vma,
			dst_addr, src_addr, false, pagep);
}

int mbsFS_mfill_zeropage_pte(struct mm_struct *dst_mm,
		pmd_t *dst_pmd,
		struct vm_area_struct *dst_vma,
		unsigned long dst_addr)
{
	struct page *page = NULL;

	return mbsFS_mfill_atomic_pte(dst_mm, dst_pmd, dst_vma,
			dst_addr, 0, true, &page);
}

static const struct inode_operations mbsFS_symlink_inode_operations;
static const struct inode_operations mbsFS_short_symlink_operations;
#endif

#ifdef CONFIG_MBSFS_XATTR
static int mbsFS_initxattrs(struct inode *, const struct xattr *, void *);
#else
#define mbsFS_initxattrs NULL
#endif
ssize_t mbsfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret > 0)
		ret = __generic_file_write_iter(iocb, from);
	inode_unlock(inode);
	return ret;
}
//EXPORT_SYMBOL(mbsFS_file_write_iter);
#if 0
int mbsfs_readpage(struct file *file, struct page *page)
{
	clear_highpage(page);
	flush_dcache_page(page);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}
static inline struct page *
mbsfs__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
	VM_WARN_ON(!node_online(nid));

	return __alloc_pages(gfp_mask, order, nid);
}
struct page *mbsfs__page_cache_alloc(gfp_t gfp)
{//when compile as a module cpuset_mem_spread_node related build error happened
	int n;
	struct page *page;

	if (cpuset_do_page_mem_spread()) {
		unsigned int cpuset_mems_cookie;
		do {
			cpuset_mems_cookie = read_mems_allowed_begin();
			n = cpuset_mem_spread_node();
			page = mbsfs__alloc_pages_node(n, gfp, 0);
		} while (!page && read_mems_allowed_retry(cpuset_mems_cookie));

		return page;
	}
	return alloc_prams(gfp, 0);
}

struct page *mbsfs_pagecache_get_page(struct address_space *mapping, pgoff_t offset,
		int fgp_flags, gfp_t gfp_mask)
{
	struct page *page;

repeat:
	page = find_get_entry(mapping, offset);
	if (radix_tree_exceptional_entry(page))//in swap area
		page = NULL;
	if (!page)
		goto no_page;

	if (fgp_flags & FGP_LOCK) {
		if (fgp_flags & FGP_NOWAIT) {
			if (!trylock_page(page)) {
				put_page(page);
				return NULL;
			}
		} else {
			lock_page(page);
		}

		/* Has the page been truncated? */
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			put_page(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page->index != offset, page);
	}

	if (page && (fgp_flags & FGP_ACCESSED))
		mark_page_accessed(page);

no_page:
	if (!page && (fgp_flags & FGP_CREAT)) {
		int err;
		if ((fgp_flags & FGP_WRITE) && mapping_cap_account_dirty(mapping))
			gfp_mask |= __GFP_WRITE;
		if (fgp_flags & FGP_NOFS)
			gfp_mask &= ~__GFP_FS;
		gfp_mask |= GFP_PRAM;
		page = mbsfs__page_cache_alloc(gfp_mask);
		if (!page)
			return NULL;

		if (WARN_ON_ONCE(!(fgp_flags & FGP_LOCK)))
			fgp_flags |= FGP_LOCK;

		/* Init accessed so avoid atomic mark_page_accessed later */
		if (fgp_flags & FGP_ACCESSED)
			__SetPageReferenced(page);

		//if (mapping->flags & __GFP_PRAM)
		err = add_to_page_cache_locked(page, mapping, offset,
				gfp_mask);//doesnot add LRU
		//else
		//	err = add_to_page_cache_lru(page, mapping, offset,
		//			gfp_mask & GFP_RECLAIM_MASK);
		if (unlikely(err)) {
			put_page(page);
			page = NULL;
			if (err == -EEXIST)
				goto repeat;
		}
	}

	return page;
}
struct page *mbsfs_grab_cache_page_write_begin(struct address_space *mapping,
		pgoff_t index, unsigned flags)
{
	struct page *page;
	int fgp_flags = FGP_LOCK|FGP_WRITE|FGP_CREAT;

	if (flags & AOP_FLAG_NOFS)
		fgp_flags |= FGP_NOFS;

	page = mbsfs_pagecache_get_page(mapping, index, fgp_flags,
			mapping_gfp_mask(mapping));
	if (page)
		wait_for_stable_page(page);

	return page;
}
#endif
	static int
mbsfs_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	//struct mbsfs_inode_info *info = MBS_I(inode);
	pgoff_t index = pos >> PAGE_SHIFT;

	/* i_mutex is held by caller */
#if 0
	if (unlikely(info->seals & (F_SEAL_WRITE | F_SEAL_GROW))) {
		if (info->seals & F_SEAL_WRITE)
			return -EPERM;
		if ((info->seals & F_SEAL_GROW) && pos + len > inode->i_size)
			return -EPERM;
	}
#endif
	return mbsfs_getpage(inode, index, pagep, MBS_WRITE);

#if 0  //simple-mbsfs
	struct page *page;

	page = mbsfs_grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	*pagep = page;

	if (!PageUptodate(page) && (len != PAGE_SIZE)) {
		unsigned from = pos & (PAGE_SIZE - 1);

		zero_user_segments(page, 0, from, from + len, PAGE_SIZE);
	}
	return 0;
#endif
}

	static int
mbsfs_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied,
		struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;

	if (pos + copied > inode->i_size)
		i_size_write(inode, pos + copied);

	if (!PageUptodate(page)) {
		struct page *head = compound_head(page);
		if (PageTransCompound(page)) {
			int i;

			for (i = 0; i < HPAGE_PMD_NR; i++) {
				if (head + i == page)
					continue;
				clear_highpage(head + i);
				flush_dcache_page(head + i);
			}
		}
		if (copied < PAGE_SIZE) {
			unsigned from = pos & (PAGE_SIZE - 1);
			zero_user_segments(page, 0, from,
					from + copied, PAGE_SIZE);
		}
		SetPageUptodate(head);
	}
#if 0						//simple-mbsfs
	struct inode *inode = page->mapping->host;
	loff_t last_pos = pos + copied;

	/* zero the stale part of the page if we did a short copy */
	if (!PageUptodate(page)) {
		if (copied < len) {
			unsigned from = pos & (PAGE_SIZE - 1);

			zero_user(page, from + copied, len - copied);
		}
		SetPageUptodate(page);
	}
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold the i_mutex.
	 */
	if (last_pos > inode->i_size)
		i_size_write(inode, last_pos);
#endif
	set_page_dirty(page);
	unlock_page(page);
	put_page(page);

	return copied;
}

static ssize_t mbsfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index;
	unsigned long offset;
	enum mbs_type mbstype = MBS_READ;
	int error = 0;
	ssize_t retval = 0;
	loff_t *ppos = &iocb->ki_pos;

	/*
	 * Might this read be for a stacking filesystem?  Then when reading
	 * holes of a sparse file, we actually need to allocate those pages,
	 * and even mark them dirty, so it cannot exceed the max_blocks limit.
	 */
	if (!iter_is_iovec(to))
		mbstype = MBS_CACHE;

	index = *ppos >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page = NULL;
		pgoff_t end_index;
		unsigned long nr, ret;
		loff_t i_size = i_size_read(inode);

		end_index = i_size >> PAGE_SHIFT;
		if (index > end_index)
			break;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset)
				break;
		}

		error = mbsfs_getpage(inode, index, &page, mbstype);
		if (error) {
			if (error == -EINVAL)
				error = 0;
			break;
		}
		if (page) {
			if (mbstype == MBS_CACHE)
				set_page_dirty(page);
			unlock_page(page);
		}

		/*
		 * We must evaluate after, since reads (unlike writes)
		 * are called without i_mutex protection against truncate
		 */
		nr = PAGE_SIZE;
		i_size = i_size_read(inode);
		end_index = i_size >> PAGE_SHIFT;
		if (index == end_index) {
			nr = i_size & ~PAGE_MASK;
			if (nr <= offset) {
				if (page)
					put_page(page);
				break;
			}
		}
		nr -= offset;

		if (page) {
			/*
			 * If users can be writing to this page using arbitrary
			 * virtual addresses, take care about potential aliasing
			 * before reading the page on the kernel side.
			 */
			if (mapping_writably_mapped(mapping))
				flush_dcache_page(page);
			/*
			 * Mark the page accessed if we read the beginning.
			 */
			if (!offset)
				mark_page_accessed(page);
		} else {
			page = ZERO_PAGE(0);
			get_page(page);
		}

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */
		ret = copy_page_to_iter(page, offset, nr, to);
		retval += ret;
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;

		put_page(page);
		if (!iov_iter_count(to))
			break;
		if (ret < nr) {
			error = -EFAULT;
			break;
		}
		cond_resched();
	}

	*ppos = ((loff_t) index << PAGE_SHIFT) + offset;
	file_accessed(file);
	return retval ? retval : error;
#if 0
	size_t count = iov_iter_count(to);
	ssize_t retval = 0;

	if (!count)
		goto out; /* skip atime */

	if (iocb->ki_flags & IOCB_DIRECT) {
		struct file *file = iocb->ki_filp;
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		loff_t size;

		size = i_size_read(inode);
		if (iocb->ki_flags & IOCB_NOWAIT) {
			if (filemap_range_has_page(mapping, iocb->ki_pos,
						iocb->ki_pos + count - 1))
				return -EAGAIN;
		} else {
			retval = filemap_write_and_wait_range(mapping,
					iocb->ki_pos,
					iocb->ki_pos + count - 1);
			if (retval < 0)
				goto out;
		}

		file_accessed(file);

		retval = mapping->a_ops->direct_IO(iocb, to);
		if (retval >= 0) {
			iocb->ki_pos += retval;
			count -= retval;
		}
		iov_iter_revert(to, count - iov_iter_count(to));

		/*
		 * Btrfs can have a short DIO read if we encounter
		 * compressed extents, so if there was an error, or if
		 * we've already read everything we wanted to, or if
		 * there was a short read because we hit EOF, go ahead
		 * and return.  Otherwise fallthrough to buffered io for
		 * the rest of the read.  Buffered reads will not work for
		 * DAX files, so don't bother trying.
		 */
		if (retval < 0 || !count || iocb->ki_pos >= size ||
				IS_DAX(inode))
			goto out;
	}
	retval = generic_file_buffered_read(iocb, to, retval);
out:
	return retval;
#endif
}

/*
 * llseek SEEK_DATA or SEEK_HOLE through the radix_tree.
 */
static pgoff_t mbsfs_seek_hole_data(struct address_space *mapping,
		pgoff_t index, pgoff_t end, int whence)
{
	struct page *page;
	struct pagevec pvec;
	pgoff_t indices[PAGEVEC_SIZE];
	bool done = false;
	int i;

	pagevec_init(&pvec, 0);
	pvec.nr = 1;		/* start small: we may be there already */
	while (!done) {
		pvec.nr = find_get_entries(mapping, index,
				pvec.nr, pvec.pages, indices);
		if (!pvec.nr) {
			if (whence == SEEK_DATA)
				index = end;
			break;
		}
		for (i = 0; i < pvec.nr; i++, index++) {
			if (index < indices[i]) {
				if (whence == SEEK_HOLE) {
					done = true;
					break;
				}
				index = indices[i];
			}
			page = pvec.pages[i];
			if (page && !radix_tree_exceptional_entry(page)) {
				if (!PageUptodate(page))
					page = NULL;
			}
			if (index >= end ||
					(page && whence == SEEK_DATA) ||
					(!page && whence == SEEK_HOLE)) {
				done = true;
				break;
			}
		}
		pagevec_remove_exceptionals(&pvec); //	mm/swap.c
		pagevec_release(&pvec);
		pvec.nr = PAGEVEC_SIZE;
		cond_resched();
	}
	return index;
}

static loff_t mbsfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t start, end;
	loff_t new_offset;

	if (whence != SEEK_DATA && whence != SEEK_HOLE)
		return generic_file_llseek_size(file, offset, whence,
				MAX_LFS_FILESIZE, i_size_read(inode));
	inode_lock(inode);
	/* We're holding i_mutex so we can access i_size directly */

	if (offset < 0)
		offset = -EINVAL;
	else if (offset >= inode->i_size)
		offset = -ENXIO;
	else {
		start = offset >> PAGE_SHIFT;
		end = (inode->i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		new_offset = mbsfs_seek_hole_data(mapping, start, end, whence);
		new_offset <<= PAGE_SHIFT;
		if (new_offset > offset) {
			if (new_offset < inode->i_size)
				offset = new_offset;
			else if (whence == SEEK_DATA)
				offset = -ENXIO;
			else
				offset = inode->i_size;
		}
	}

	if (offset >= 0)
		offset = vfs_setpos(file, offset, MAX_LFS_FILESIZE);
	inode_unlock(inode);
	return offset;
}
#if 0
/*
 * We need a tag: a new tag would expand every radix_tree_node by 8 bytes,
 * so reuse a tag which we firmly believe is never set or cleared on mbsFS.
 */
#define MBS_TAG_PINNED        PAGECACHE_TAG_TOWRITE
#define LAST_SCAN               4       /* about 150ms max */

static void mbsFS_tag_pins(struct address_space *mapping)
{
	struct radix_tree_iter iter;
	void **slot;
	pgoff_t start;
	struct page *page;

	lru_add_drain();
	start = 0;
	rcu_read_lock();

	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		page = radix_tree_deref_slot(slot);
		if (!page || radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
		} else if (page_count(page) - page_mapcount(page) > 1) {
			spin_lock_irq(&mapping->tree_lock);
			radix_tree_tag_set(&mapping->page_tree, iter.index,
					MBS_TAG_PINNED);
			spin_unlock_irq(&mapping->tree_lock);
		}

		if (need_resched()) {
			slot = radix_tree_iter_resume(slot, &iter);
			cond_resched_rcu();
		}
	}
	rcu_read_unlock();
}

/*
 * Setting SEAL_WRITE requires us to verify there's no pending writer. However,
 * via get_user_pages(), drivers might have some pending I/O without any active
 * user-space mappings (eg., direct-IO, AIO). Therefore, we look at all pages
 * and see whether it has an elevated ref-count. If so, we tag them and wait for
 * them to be dropped.
 * The caller must guarantee that no new user will acquire writable references
 * to those pages to avoid races.
 */
static int mbsFS_wait_for_pins(struct address_space *mapping)
{
	struct radix_tree_iter iter;
	void **slot;
	pgoff_t start;
	struct page *page;
	int error, scan;

	mbsFS_tag_pins(mapping);

	error = 0;
	for (scan = 0; scan <= LAST_SCAN; scan++) {
		if (!radix_tree_tagged(&mapping->page_tree, MBS_TAG_PINNED))
			break;

		if (!scan)
			lru_add_drain_all();
		else if (schedule_timeout_killable((HZ << scan) / 200))
			scan = LAST_SCAN;

		start = 0;
		rcu_read_lock();
		radix_tree_for_each_tagged(slot, &mapping->page_tree, &iter,
				start, MBS_TAG_PINNED) {

			page = radix_tree_deref_slot(slot);
			if (radix_tree_exception(page)) {
				if (radix_tree_deref_retry(page)) {
					slot = radix_tree_iter_retry(&iter);
					continue;
				}

				page = NULL;
			}

			if (page &&
					page_count(page) - page_mapcount(page) != 1) {
				if (scan < LAST_SCAN)
					goto continue_resched;

				/*
				 * On the last scan, we clean up all those tags
				 * we inserted; but make a note that we still
				 * found pages pinned.
				 */
				error = -EBUSY;
			}

			spin_lock_irq(&mapping->tree_lock);
			radix_tree_tag_clear(&mapping->page_tree,
					iter.index, MBS_TAG_PINNED);
			spin_unlock_irq(&mapping->tree_lock);
continue_resched:
			if (need_resched()) {
				slot = radix_tree_iter_resume(slot, &iter);
				cond_resched_rcu();
			}
		}
		rcu_read_unlock();
	}

	return error;
}

#define F_ALL_SEALS (F_SEAL_SEAL | \
		F_SEAL_SHRINK | \
		F_SEAL_GROW | \
		F_SEAL_WRITE)

int mbsFS_add_seals(struct file *file, unsigned int seals)
{
	struct inode *inode = file_inode(file);
	struct mbsfs_inode_info *info = MBS_I(inode);
	int error;

	/*
	 * SEALING
	 * Sealing allows multiple parties to share a mbsFS-file but restrict
	 * access to a specific subset of file operations. Seals can only be
	 * added, but never removed. This way, mutually untrusted parties can
	 * share common memory regions with a well-defined policy. A malicious
	 * peer can thus never perform unwanted operations on a MBS object.
	 *
	 * Seals are only supported on special mbsFS-files and always affect
	 * the whole underlying inode. Once a seal is set, it may prevent some
	 * kinds of access to the file. Currently, the following seals are
	 * defined:
	 *   SEAL_SEAL: Prevent further seals from being set on this file
	 *   SEAL_SHRINK: Prevent the file from shrinking
	 *   SEAL_GROW: Prevent the file from growing
	 *   SEAL_WRITE: Prevent write access to the file
	 *
	 * As we don't require any trust relationship between two parties, we
	 * must prevent seals from being removed. Therefore, sealing a file
	 * only adds a given set of seals to the file, it never touches
	 * existing seals. Furthermore, the "setting seals"-operation can be
	 * sealed itself, which basically prevents any further seal from being
	 * added.
	 *
	 * Semantics of sealing are only defined on volatile files. Only
	 * anonymous mbsFS files support sealing. More importantly, seals are
	 * never written to disk. Therefore, there's no plan to support it on
	 * other file types.
	 */

	if (file->f_op != &mbsfs_file_operations)
		return -EINVAL;
	if (!(file->f_mode & FMODE_WRITE))
		return -EPERM;
	if (seals & ~(unsigned int)F_ALL_SEALS)
		return -EINVAL;

	inode_lock(inode);

	if (info->seals & F_SEAL_SEAL) {
		error = -EPERM;
		goto unlock;
	}

	if ((seals & F_SEAL_WRITE) && !(info->seals & F_SEAL_WRITE)) {
		error = mapping_deny_writable(file->f_mapping);
		if (error)
			goto unlock;

		error = mbsFS_wait_for_pins(file->f_mapping);
		if (error) {
			mapping_allow_writable(file->f_mapping);
			goto unlock;
		}
	}

	info->seals |= seals;
	error = 0;

unlock:
	inode_unlock(inode);
	return error;
}

//EXPORT_SYMBOL_GPL(mbsFS_add_seals);

int mbsFS_get_seals(struct file *file)
{
	if (file->f_op != &mbsfs_file_operations)
		return -EINVAL;

	return MBS_I(file_inode(file))->seals;
}
//EXPORT_SYMBOL_GPL(mbsFS_get_seals);

long mbsFS_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long error;

	switch (cmd) {
		case F_ADD_SEALS:
			/* disallow upper 32bit */
			if (arg > UINT_MAX)
				return -EINVAL;

			error = mbsFS_add_seals(file, arg);
			break;
		case F_GET_SEALS:
			error = mbsFS_get_seals(file);
			break;
		default:
			error = -EINVAL;
			break;
	}

	return error;
}
static long mbsfs_fallocate(struct file *file, int mode, loff_t offset,
		loff_t len)
{
	struct inode *inode = file_inode(file);
	struct mbsfs_sb_info *sbinfo = MBS_SB(inode->i_sb);
	struct mbsfs_inode_info *info = MBS_I(inode);
	struct mbsfs_falloc mbsFS_falloc;
	pgoff_t start, index, end;
	int error;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	inode_lock(inode);

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		struct address_space *mapping = file->f_mapping;
		loff_t unmap_start = round_up(offset, PAGE_SIZE);
		loff_t unmap_end = round_down(offset + len, PAGE_SIZE) - 1;
		DECLARE_WAIT_QUEUE_HEAD_ONSTACK(mbsFS_falloc_waitq);

		/* protected by i_mutex */
		if (info->seals & F_SEAL_WRITE) {
			error = -EPERM;
			goto out;
		}

		mbsFS_falloc.waitq = &mbsFS_falloc_waitq;
		mbsFS_falloc.start = unmap_start >> PAGE_SHIFT;
		mbsFS_falloc.next = (unmap_end + 1) >> PAGE_SHIFT;
		spin_lock(&inode->i_lock);
		inode->i_private = &mbsFS_falloc;
		spin_unlock(&inode->i_lock);

		if ((u64)unmap_end > (u64)unmap_start)
			unmap_mapping_range(mapping, unmap_start,
					1 + unmap_end - unmap_start, 0);
		mbsfs_truncate_range(inode, offset, offset + len - 1);
		/* No need to unmap again: hole-punching leaves COWed pages */

		spin_lock(&inode->i_lock);
		inode->i_private = NULL;
		wake_up_all(&mbsFS_falloc_waitq);
		WARN_ON_ONCE(!list_empty(&mbsFS_falloc_waitq.head));
		spin_unlock(&inode->i_lock);
		error = 0;
		goto out;
	}

	/* We need to check rlimit even when FALLOC_FL_KEEP_SIZE */
	error = inode_newsize_ok(inode, offset + len);
	if (error)
		goto out;

	if ((info->seals & F_SEAL_GROW) && offset + len > inode->i_size) {
		error = -EPERM;
		goto out;
	}

	start = offset >> PAGE_SHIFT;
	end = (offset + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	/* Try to avoid a swapstorm if len is impossible to satisfy */
	if (sbinfo->max_blocks && end - start > sbinfo->max_blocks) {
		error = -ENOSPC;
		goto out;
	}

	mbsFS_falloc.waitq = NULL;
	mbsFS_falloc.start = start;
	mbsFS_falloc.next  = start;
	mbsFS_falloc.nr_falloced = 0;
	mbsFS_falloc.nr_unswapped = 0;
	spin_lock(&inode->i_lock);
	inode->i_private = &mbsFS_falloc;
	spin_unlock(&inode->i_lock);

	for (index = start; index < end; index++) {
		struct page *page;

		/*
		 * Good, the fallocate(2) manpage permits EINTR: we may have
		 * been interrupted because we are using up too much memory.
		 */
		if (signal_pending(current))
			error = -EINTR;
		else if (mbsFS_falloc.nr_unswapped > mbsFS_falloc.nr_falloced)
			error = -ENOMEM;
		else
			error = mbsfs_getpage(inode, index, &page, MBS_FALLOC);
		if (error) {
			/* Remove the !PageUptodate pages we added */
			if (index > start) {
				mbsfs_undo_range(inode,
						(loff_t)start << PAGE_SHIFT,
						((loff_t)index << PAGE_SHIFT) - 1, true);
			}
			goto undone;
		}

		/*
		 * Inform mbsFS_writepage() how far we have reached.
		 * No need for lock or barrier: we have the page lock.
		 */
		mbsFS_falloc.next++;
		if (!PageUptodate(page))
			mbsFS_falloc.nr_falloced++;

		/*
		 * If !PageUptodate, leave it that way so that freeable pages
		 * can be recognized if we need to rollback on error later.
		 * But set_page_dirty so that memory pressure will swap rather
		 * than free the pages we are allocating (and MBS_CACHE pages
		 * might still be clean: we now need to mark those dirty too).
		 */
		set_page_dirty(page);
		unlock_page(page);
		put_page(page);
		cond_resched();
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && offset + len > inode->i_size)
		i_size_write(inode, offset + len);
	inode->i_ctime = current_time(inode);
undone:
	spin_lock(&inode->i_lock);
	inode->i_private = NULL;
	spin_unlock(&inode->i_lock);
out:
	inode_unlock(inode);
	return error;
}
#endif

static int mbsfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct mbsfs_sb_info *sbinfo = MBS_SB(dentry->d_sb);

	buf->f_type = dentry->d_sb->s_magic;//MBSFS_MAGIC;
	buf->f_bsize = PAGE_SIZE;
	buf->f_namelen = NAME_MAX;
	//#if 0								//rNO
	if (sbinfo->max_blocks) {
		buf->f_blocks = sbinfo->max_blocks;
		buf->f_bavail =
			buf->f_bfree  = sbinfo->max_blocks -
			percpu_counter_sum(&sbinfo->used_blocks);
	}
	if (sbinfo->max_inodes) {
		buf->f_files = sbinfo->max_inodes;
		buf->f_ffree = sbinfo->free_inodes;
	}
	/* else leave those fields 0 like simple_statfs */
	//#endif							//rNO
	return 0;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
	static int
mbsfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode *inode;
	int error = -ENOSPC;

	inode = mbsfs_get_inode(dir->i_sb, dir, mode, dev, 0);
	if (inode) {
		d_instantiate(dentry, inode);
		dget(dentry); /* Extra count - pin the dentry in core */
		error = 0;
		dir->i_size += BOGO_DIRENT_SIZE;		//rNO
		dir->i_ctime = dir->i_mtime = current_time(dir);
	}
	return error;
}
#if 0
static int
mbsFS_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	int error = -ENOSPC;

	inode = mbsFS_get_inode(dir->i_sb, dir, mode, 0, VM_NORESERVE);
	if (inode) {
		error = security_inode_init_security(inode, dir,
				NULL,
				mbsFS_initxattrs, NULL);
		if (error && error != -EOPNOTSUPP)
			goto out_iput;
		error = simple_acl_create(dir, inode);
		if (error)
			goto out_iput;
		d_tmpfile(dentry, inode);
	}
	return error;
out_iput:
	iput(inode);
	return error;
}
#endif
static int mbsfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int error = mbsfs_mknod(dir, dentry, mode | S_IFDIR, 0);

	if (!error)
		inc_nlink(dir);
	return error;
}

static int mbsfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	return mbsfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

/*
 * Link a file..
 */
static int mbsfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);
	int ret=0;

	/*
	 * No ordinary (disk based) filesystem counts links as inodes;
	 * but each new link needs a new dentry, pinning lowmem, and
	 * mbsfs dentries cannot be pruned until they are unlinked.
	 */

	dir->i_size += BOGO_DIRENT_SIZE;		//rNO
	inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
	inc_nlink(inode);
	ihold(inode);	/* New dentry reference */
	dget(dentry);		/* Extra pinning count for the created dentry */
	d_instantiate(dentry, inode);
	return ret;
}

static int mbsfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	dir->i_size -= BOGO_DIRENT_SIZE;		//rNO
	inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
	drop_nlink(inode);
	dput(dentry);	/* Undo the count from "create" - this does all the work */
	return 0;
}

static int mbsfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!simple_empty(dentry))
		return -ENOTEMPTY;

	drop_nlink(d_inode(dentry));
	mbsfs_unlink(dir, dentry);
	drop_nlink(dir);
	return 0; 
}
#if 0
static int mbsFS_exchange(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
	bool old_is_dir = d_is_dir(old_dentry);
	bool new_is_dir = d_is_dir(new_dentry);

	if (old_dir != new_dir && old_is_dir != new_is_dir) {
		if (old_is_dir) {
			drop_nlink(old_dir);
			inc_nlink(new_dir);
		} else {
			drop_nlink(new_dir);
			inc_nlink(old_dir);
		}
	}
	old_dir->i_ctime = old_dir->i_mtime =
		new_dir->i_ctime = new_dir->i_mtime =
		d_inode(old_dentry)->i_ctime =
		d_inode(new_dentry)->i_ctime = current_time(old_dir);

	return 0;
}

static int mbsFS_whiteout(struct inode *old_dir, struct dentry *old_dentry)
{
	struct dentry *whiteout;
	int error;

	whiteout = d_alloc(old_dentry->d_parent, &old_dentry->d_name);
	if (!whiteout)
		return -ENOMEM;

	error = mbsFS_mknod(old_dir, whiteout,
			S_IFCHR | WHITEOUT_MODE, WHITEOUT_DEV);
	dput(whiteout);
	if (error)
		return error;

	/*
	 * Cheat and hash the whiteout while the old dentry is still in
	 * place, instead of playing games with FS_RENAME_DOES_D_MOVE.
	 *
	 * d_lookup() will consistently find one of them at this point,
	 * not sure which one, but that isn't even important.
	 */
	d_rehash(whiteout);
	return 0;
}
#endif
/*
 * The VFS layer already does all the dentry stuff for rename,
 * we just have to decrement the usage count for the target if
 * it exists so that the VFS layer correctly free's it when it
 * gets overwritten.
 */
static int mbsfs_rename2(struct inode *old_dir, struct dentry *old_dentry, 
		struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct inode *inode = d_inode(old_dentry);
	int they_are_dirs = S_ISDIR(inode->i_mode);

	if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
		return -EINVAL;
#if 0
	if (flags & RENAME_EXCHANGE)			//rNO
		return mbsFS_exchange(old_dir, old_dentry, new_dir, new_dentry);
#endif
	if (!simple_empty(new_dentry))
		return -ENOTEMPTY;
#if 0
	if (flags & RENAME_WHITEOUT) {			//rNO
		int error;

		error = mbsFS_whiteout(old_dir, old_dentry);
		if (error)
			return error;
	}
#endif
	if (d_really_is_positive(new_dentry)) {
		(void) mbsfs_unlink(new_dir, new_dentry);
		if (they_are_dirs) {
			drop_nlink(d_inode(new_dentry));
			drop_nlink(old_dir);
		}
	} else if (they_are_dirs) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}

	//old_dir->i_size -= BOGO_DIRENT_SIZE;
	//new_dir->i_size += BOGO_DIRENT_SIZE;
	old_dir->i_ctime = old_dir->i_mtime =
		new_dir->i_ctime = new_dir->i_mtime =
		inode->i_ctime = current_time(old_dir);
	return 0;
}
/*
 * The nofs argument instructs pagecache_write_begin to pass AOP_FLAG_NOFS
 */
int __mbsfs_page_symlink(struct inode *inode, const char *symname, int len, int nofs)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	void *fsdata;
	int err;
	unsigned int flags = 0;
	if (nofs)
		flags |= AOP_FLAG_NOFS;

retry:
	err = pagecache_write_begin(NULL, mapping, 0, len-1,
			flags, &page, &fsdata);
	if (err)
		goto fail;

	memcpy(page_address(page), symname, len-1);

	err = pagecache_write_end(NULL, mapping, 0, len-1, len-1,
			page, fsdata);
	if (err < 0)
		goto fail;
	if (err < len-1)
		goto retry;

	mark_inode_dirty(inode);
	return 0;
fail:
	return err;
}

int mbsfs_page_symlink(struct inode *inode, const char *symname, int len)
{
	return __mbsfs_page_symlink(inode, symname, len,
			!mapping_gfp_constraint(inode->i_mapping, __GFP_FS));
}
static int mbsfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	struct inode *inode;
	int error = -ENOSPC;
	int len;
	//struct page *page;

	inode = mbsfs_get_inode(dir->i_sb, dir, S_IFLNK|S_IRWXUGO, 0,0);
	if (!inode)
		return -ENOSPC;

	len = strlen(symname) + 1;
	if (len > PAGE_SIZE)
		return -ENAMETOOLONG;

	error = mbsfs_page_symlink(inode, symname, len);
	if (!error) {
		d_instantiate(dentry, inode);
		dget(dentry);
		dir->i_mtime = dir->i_ctime = current_time(dir);
	} else
		iput(inode);

	return error;
}
#if 0
static void mbsFS_put_link(void *arg)
{
	mark_page_accessed(arg);
	put_page(arg);
}

static const char *mbsFS_get_link(struct dentry *dentry,
		struct inode *inode,
		struct delayed_call *done)
{
	struct page *page = NULL;
	int error;
	if (!dentry) {
		page = find_get_page(inode->i_mapping, 0);
		if (!page)
			return ERR_PTR(-ECHILD);
		if (!PageUptodate(page)) {
			put_page(page);
			return ERR_PTR(-ECHILD);
		}
	} else {
		error = mbsfs_getpage(inode, 0, &page, MBS_READ);
		if (error)
			return ERR_PTR(error);
		unlock_page(page);
	}
	set_delayed_call(done, mbsFS_put_link, page);
	return page_address(page);
}

#ifdef CONFIG_MBSFS_XATTR
/*
 * Superblocks without xattr inode operations may get some security.* xattr
 * support from the LSM "for free". As soon as we have any other xattrs
 * like ACLs, we also need to implement the security.* handlers at
 * filesystem level, though.
 */

/*
 * Callback for security_inode_init_security() for acquiring xattrs.
 */

static int mbsFS_initxattrs(struct inode *inode,
		const struct xattr *xattr_array,
		void *fs_info)
{
	struct mbsfs_inode_info *info = MBS_I(inode);
	const struct xattr *xattr;
	struct simple_xattr *new_xattr;
	size_t len;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		new_xattr = simple_xattr_alloc(xattr->value, xattr->value_len);
		if (!new_xattr)
			return -ENOMEM;

		len = strlen(xattr->name) + 1;
		new_xattr->name = kmalloc(XATTR_SECURITY_PREFIX_LEN + len,
				GFP_KERNEL);
		if (!new_xattr->name) {
			kfree(new_xattr);
			return -ENOMEM;
		}

		memcpy(new_xattr->name, XATTR_SECURITY_PREFIX,
				XATTR_SECURITY_PREFIX_LEN);
		memcpy(new_xattr->name + XATTR_SECURITY_PREFIX_LEN,
				xattr->name, len);

		simple_xattr_list_add(&info->xattrs, new_xattr);
	}

	return 0;
}
#endif
static int mbsFS_xattr_handler_get(const struct xattr_handler *handler,
		struct dentry *unused, struct inode *inode,
		const char *name, void *buffer, size_t size)
{
	struct mbsfs_inode_info *info = MBS_I(inode);

	name = xattr_full_name(handler, name);
	return simple_xattr_get(&info->xattrs, name, buffer, size);
}

static int mbsFS_xattr_handler_set(const struct xattr_handler *handler,
		struct dentry *unused, struct inode *inode,
		const char *name, const void *value,
		size_t size, int flags)
{
	struct mbsfs_inode_info *info = MBS_I(inode);

	name = xattr_full_name(handler, name);
	return simple_xattr_set(&info->xattrs, name, value, size, flags);
}

static const struct xattr_handler mbsFS_security_xattr_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.get = mbsFS_xattr_handler_get,
	.set = mbsFS_xattr_handler_set,
};

static const struct xattr_handler mbsFS_trusted_xattr_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.get = mbsFS_xattr_handler_get,
	.set = mbsFS_xattr_handler_set,
};

static const struct xattr_handler *mbsFS_xattr_handlers[] = {
#ifdef CONFIG_MBSFS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
	&mbsFS_security_xattr_handler,
	&mbsFS_trusted_xattr_handler,
	NULL
};

static ssize_t mbsFS_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct mbsfs_inode_info *info = MBS_I(d_inode(dentry));
	return simple_xattr_list(d_inode(dentry), &info->xattrs, buffer, size);
}
//#endif /* CONFIG_MBSFS_XATTR */

static const struct inode_operations mbsFS_short_symlink_operations = {
	.get_link	= simple_get_link,
#ifdef CONFIG_MBSFS_XATTR
	.listxattr	= mbsFS_listxattr,
#endif
};

static const struct inode_operations mbsFS_symlink_inode_operations = {
	.get_link	= mbsFS_get_link,
#ifdef CONFIG_MBSFS_XATTR
	.listxattr	= mbsFS_listxattr,
#endif
};


static struct dentry *mbsFS_get_parent(struct dentry *child)
{
	return ERR_PTR(-ESTALE);
}

static int mbsFS_match(struct inode *ino, void *vfh)
{
	__u32 *fh = vfh;
	__u64 inum = fh[2];
	inum = (inum << 32) | fh[1];
	return ino->i_ino == inum && fh[0] == ino->i_generation;
}

static struct dentry *mbsFS_fh_to_dentry(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct inode *inode;
	struct dentry *dentry = NULL;
	u64 inum;

	if (fh_len < 3)
		return NULL;

	inum = fid->raw[2];
	inum = (inum << 32) | fid->raw[1];

	inode = ilookup5(sb, (unsigned long)(inum + fid->raw[0]),
			mbsFS_match, fid->raw);
	if (inode) {
		dentry = d_find_alias(inode);
		iput(inode);
	}

	return dentry;
}

static int mbsFS_encode_fh(struct inode *inode, __u32 *fh, int *len,
		struct inode *parent)
{
	if (*len < 3) {
		*len = 3;
		return FILEID_INVALID;
	}

	if (inode_unhashed(inode)) {
		/* Unfortunately insert_inode_hash is not idempotent,
		 * so as we hash inodes here rather than at creation
		 * time, we need a lock to ensure we only try
		 * to do it once
		 */
		static DEFINE_SPINLOCK(lock);
		spin_lock(&lock);
		if (inode_unhashed(inode))
			__insert_inode_hash(inode,
					inode->i_ino + inode->i_generation);
		spin_unlock(&lock);
	}

	fh[0] = inode->i_generation;
	fh[1] = inode->i_ino;
	fh[2] = ((__u64)inode->i_ino) >> 32;

	*len = 3;
	return 1;
}

static const struct export_operations mbsFS_export_ops = {
	.get_parent     = mbsFS_get_parent,
	.encode_fh      = mbsFS_encode_fh,
	.fh_to_dentry	= mbsFS_fh_to_dentry,
};

#endif
static int mbsfs_parse_options(char *options, struct mbsfs_sb_info *sbinfo,
		bool remount)
{
	char *this_char, *value, *rest;
	struct mempolicy *mpol = NULL;
	uid_t uid;
	gid_t gid;

	//sbinfo->mode = MBSFS_DEFAULT_MODE; //choose simple or comple, now simple
	while (options != NULL) {
		this_char = options;
		for (;;) {
			/*
			 * NUL-terminate this option: unfortunately,
			 * mount options form a comma-separated list,
			 * but mpol's nodelist may also contain commas.
			 */
			options = strchr(options, ',');
			if (options == NULL)
				break;
			options++;
			if (!isdigit(*options)) {
				options[-1] = '\0';
				break;
			}
		}
		if (!*this_char)
			continue;
		if ((value = strchr(this_char,'=')) != NULL) {
			*value++ = 0;
		} else {
			pr_err("mbsfs: No value for mount option '%s'\n",
					this_char);
			goto error;
		}

		totalpram_pages=memblock.pram.total_size / PAGE_SIZE;//convert to pages

		if (!strcmp(this_char,"size")) {
			unsigned long long size;
			size = memparse(value,&rest);
			if (*rest == '%') {
				size <<= PAGE_SHIFT;
				size *= totalpram_pages;
				do_div(size, 100);
				rest++;
			}
			if (*rest)
				goto bad_val;
			sbinfo->max_blocks =
				DIV_ROUND_UP(size, PAGE_SIZE);
		} else if (!strcmp(this_char,"nr_blocks")) {
			sbinfo->max_blocks = memparse(value, &rest);
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"nr_inodes")) {
			sbinfo->max_inodes = memparse(value, &rest);
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"mode")) {
			if (remount)
				continue;
			sbinfo->mode = simple_strtoul(value, &rest, 8) & 07777;
			if (*rest)
				goto bad_val;
		} else if (!strcmp(this_char,"uid")) {
			if (remount)
				continue;
			uid = simple_strtoul(value, &rest, 0);
			if (*rest)
				goto bad_val;
			sbinfo->uid = make_kuid(current_user_ns(), uid);
			if (!uid_valid(sbinfo->uid))
				goto bad_val;
		} else if (!strcmp(this_char,"gid")) {
			if (remount)
				continue;
			gid = simple_strtoul(value, &rest, 0);
			if (*rest)
				goto bad_val;
			sbinfo->gid = make_kgid(current_user_ns(), gid);
			if (!gid_valid(sbinfo->gid))
				goto bad_val;
#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
		} else if (!strcmp(this_char, "huge")) {
			int huge;
			huge = mbsfs_parse_huge(value);
			if (huge < 0)
				goto bad_val;
			if (!has_transparent_hugepage() &&
					huge != MBS_HUGE_NEVER)
				goto bad_val;
			sbinfo->huge = huge;
#endif
#ifdef CONFIG_NUMA
		} else if (!strcmp(this_char,"flag")) {
			mpol_put_pram(mpol);
			mpol = NULL;
			if (mpol_parse_str_pram(value, &mpol))
				goto bad_val;
#endif
		} else {
			pr_err("mbsfs: Bad mount option %s\n", this_char);
			goto error;
		}
	}
	sbinfo->mpol = mpol;
	return 0;
bad_val:
	pr_err("mbsfs: Bad value '%s' for mount option '%s'\n",
			value, this_char);
error:
	mpol_put_pram(mpol);
	return 1;

#if 0 //simple-mbs-fs
	substring_t args[MAX_OPT_ARGS];
	int option;
	int token;
	char *p;


	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
			case Opt_mode:
				if (match_octal(&args[0], &option))
					return -EINVAL;
				opts->mode = option & S_IALLUGO;
				break;
				/*
				 * We might like to report bad mount options here;
				 * but traditionally ramfs has ignored all mount options,
				 * and as it is used as a !CONFIG_SHMEM simple substitute
				 * for tmpfs, better continue to ignore other mount options.
				 */
		}
	}
	return 0;
#endif
}
#if 0
static int mbsFS_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct mbsfs_sb_info *sbinfo = MBS_SB(sb);
	struct mbsfs_sb_info config = *sbinfo;
	unsigned long inodes;
	int error = -EINVAL;

	config.mpol = NULL;
	if (mbsFS_parse_options(data, &config, true))
		return error;

	spin_lock(&sbinfo->stat_lock);
	inodes = sbinfo->max_inodes - sbinfo->free_inodes;
	if (percpu_counter_compare(&sbinfo->used_blocks, config.max_blocks) > 0)
		goto out;
	if (config.max_inodes < inodes)
		goto out;
	/*
	 * Those tests disallow limited->unlimited while any are in use;
	 * but we must separately disallow unlimited->limited, because
	 * in that case we have no record of how much is already in use.
	 */
	if (config.max_blocks && !sbinfo->max_blocks)
		goto out;
	if (config.max_inodes && !sbinfo->max_inodes)
		goto out;

	error = 0;
	sbinfo->huge = config.huge;
	sbinfo->max_blocks  = config.max_blocks;
	sbinfo->max_inodes  = config.max_inodes;
	sbinfo->free_inodes = config.max_inodes - inodes;

	/*
	 * Preserve previous prampolicy unless mpol remount option was specified.
	 */
	if (config.mpol) {
		mpol_put(sbinfo->mpol);
		//mpol_put_pram(sbinfo->mpol);
		sbinfo->mpol = config.mpol;	/* transfers initial ref */
	}
out:
	spin_unlock(&sbinfo->stat_lock);
	return error;
}
#endif

static int mbsfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct mbsfs_fs_info *fsi = root->d_sb->s_fs_info;
	struct mbsfs_sb_info *sbinfo = MBS_SB(root->d_sb);

	if (fsi->mount_opts.mode != MBSFS_DEFAULT_MODE)
		seq_printf(seq, ",mode=%o", fsi->mount_opts.mode);

	if (sbinfo->max_blocks != mbsfs_default_max_blocks())
		seq_printf(seq, ",size=%luk",
				sbinfo->max_blocks << (PAGE_SHIFT - 10));
	if (sbinfo->max_inodes != mbsfs_default_max_inodes())
		seq_printf(seq, ",nr_inodes=%lu", sbinfo->max_inodes);
	if (sbinfo->mode != (S_IRWXUGO | S_ISVTX))
		seq_printf(seq, ",mode=%03ho", sbinfo->mode);
	if (!uid_eq(sbinfo->uid, GLOBAL_ROOT_UID))
		seq_printf(seq, ",uid=%u",
				from_kuid_munged(&init_user_ns, sbinfo->uid));
	if (!gid_eq(sbinfo->gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u",
				from_kgid_munged(&init_user_ns, sbinfo->gid));
#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
	/* Rightly or wrongly, show huge mount option unmasked by mbsFS_huge */
	if (sbinfo->huge)
		seq_printf(seq, ",huge=%s", mbsfs_format_huge(sbinfo->huge));
#endif
	mbsfs_show_mpol(seq, sbinfo->mpol);
	return 0;
}

#if 0

#define MFD_NAME_PREFIX "memfd:"
#define MFD_NAME_PREFIX_LEN (sizeof(MFD_NAME_PREFIX) - 1)
#define MFD_NAME_MAX_LEN (NAME_MAX - MFD_NAME_PREFIX_LEN)

#define MFD_ALL_FLAGS (MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB)

SYSCALL_DEFINE2(memfd_create,
		const char __user *, uname,
		unsigned int, flags)
{
	struct mbsfs_inode_info *info;
	struct file *file;
	int fd, error;
	char *name;
	long len;

	if (!(flags & MFD_HUGETLB)) {
		if (flags & ~(unsigned int)MFD_ALL_FLAGS)
			return -EINVAL;
	} else {
		/* Sealing not supported in hugetlbfs (MFD_HUGETLB) */
		if (flags & MFD_ALLOW_SEALING)
			return -EINVAL;
		/* Allow huge page size encoding in flags. */
		if (flags & ~(unsigned int)(MFD_ALL_FLAGS |
					(MFD_HUGE_MASK << MFD_HUGE_SHIFT)))
			return -EINVAL;
	}

	/* length includes terminating zero */
	len = strnlen_user(uname, MFD_NAME_MAX_LEN + 1);
	if (len <= 0)
		return -EFAULT;
	if (len > MFD_NAME_MAX_LEN + 1)
		return -EINVAL;

	name = kmalloc(len + MFD_NAME_PREFIX_LEN, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	strcpy(name, MFD_NAME_PREFIX);
	if (copy_from_user(&name[MFD_NAME_PREFIX_LEN], uname, len)) {
		error = -EFAULT;
		goto err_name;
	}

	/* terminating-zero may have changed after strnlen_user() returned */
	if (name[len + MFD_NAME_PREFIX_LEN - 1]) {
		error = -EFAULT;
		goto err_name;
	}

	fd = get_unused_fd_flags((flags & MFD_CLOEXEC) ? O_CLOEXEC : 0);
	if (fd < 0) {
		error = fd;
		goto err_name;
	}

	if (flags & MFD_HUGETLB) {
		//struct user_struct *user = NULL;
		file = ERR_PTR(-ENOSYS) ;
		/*
		   file = hugetlb_file_setup(name, 0, VM_NORESERVE, &user,
		   HUGETLB_ANONHUGE_INODE,
		   (flags >> MFD_HUGE_SHIFT) &
		   MFD_HUGE_MASK);
		   */
	} else
		file = mbsFS_file_setup(name, 0, VM_NORESERVE);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto err_fd;
	}
	file->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
	file->f_flags |= O_RDWR | O_LARGEFILE;

	if (flags & MFD_ALLOW_SEALING) {
		/*
		 * flags check at beginning of function ensures
		 * this is not a hugetlbfs (MFD_HUGETLB) file.
		 */
		info = MBS_I(file_inode(file));
		info->seals &= ~F_SEAL_SEAL;
	}

	fd_install(fd, file);
	kfree(name);
	return fd;

err_fd:
	put_unused_fd(fd);
err_name:
	kfree(name);
	return error;
}
#endif

static void mbsfs_put_super(struct super_block *sb)
{
	struct mbsfs_sb_info *sbinfo = MBS_SB(sb);

	percpu_counter_destroy(&sbinfo->used_blocks);
	////mpol_put(sbinfo->mpol);
	mpol_put_pram(sbinfo->mpol);
	kfree(sbinfo);
	sb->s_fs_info = NULL;
}

int mbsfs_fill_super(struct super_block *sb, void *data, int silent)
{
	//struct mbsfs_fs_info *fsi;
	struct inode *inode;
	struct mbsfs_sb_info *sbinfo;			//rNO
	int err = -ENOMEM;

	/* Round up to L1_CACHE_BYTES to resist false sharing */
	sbinfo = kzalloc(max((int)sizeof(struct mbsfs_sb_info), L1_CACHE_BYTES),
			GFP_KERNEL);
	if (!sbinfo)
		return -ENOMEM;

	sbinfo->mode = S_IRWXUGO | S_ISVTX;
	sbinfo->uid = current_fsuid();
	sbinfo->gid = current_fsgid();
	sb->s_fs_info = sbinfo;
	/* simple-mbsfs
	   fsi = kzalloc(sizeof(struct mbsfs_fs_info), GFP_KERNEL);
	   sb->s_fs_info = fsi;
	   if (!fsi)
	   return -ENOMEM;
	   err = mbsfs_parse_options(data, sbinfo, false, &fsi->mount_opts);
	   if (err)
	   return err;
	   inode = mbsfs_get_inode(sb, NULL, S_IFDIR | fsi->mount_opts.mode, 0,VM_NONE);
	   */
	/*
	 * Per default we allow the physical pram per
	 * mbsfs instance, limiting inodes to one per page of lowmem;
	 * but the internal instance is left unlimited.
	 */
	if (!(sb->s_flags & MS_KERNMOUNT)) {
		sbinfo->max_blocks = mbsfs_default_max_blocks();
		sbinfo->max_inodes = mbsfs_default_max_inodes();
		if (mbsfs_parse_options(data, sbinfo, false)) {
			err = -EINVAL;
			goto failed;
		}
	}else{
		sb->s_flags |= MS_NOUSER;
	}
	//sb->s_export_op = &mbsFS_export_ops;		//nfs related
	sb->s_flags |= MS_NOSEC;

	spin_lock_init(&sbinfo->stat_lock);
	if (percpu_counter_init(&sbinfo->used_blocks, 0, GFP_KERNEL))
		goto failed;
	sbinfo->free_inodes = sbinfo->max_inodes;
	//	spin_lock_init(&sbinfo->shrinklist_lock);
	//	INIT_LIST_HEAD(&sbinfo->shrinklist);

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_blocksize		= PAGE_SIZE;
	sb->s_blocksize_bits	= PAGE_SHIFT;
	sb->s_blocksize		= PAGE_SIZE * (1UL << ORDERS);
	sb->s_blocksize_bits	= PAGE_SHIFT + ORDERS ;
	sb->s_magic		= MBSFS_MAGIC;
	sb->s_op		= &mbsfs_ops;
	sb->s_time_gran		= 1;
#ifdef CONFIG_MBSFS_XATTR
	sb->s_xattr = mbsfs_xattr_handlers;
#endif
#ifdef CONFIG_MBSFS_POSIX_ACL
	sb->s_flags |= MS_POSIXACL;
#endif
	uuid_gen(&sb->s_uuid);					//rNO
	inode = mbsfs_get_inode(sb, NULL, S_IFDIR | sbinfo->mode, 0, VM_NONE);
	if (!inode)
		goto failed;
	inode->i_uid = sbinfo->uid;
	inode->i_gid = sbinfo->gid;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		goto failed;
	return 0;
failed:
	mbsfs_put_super(sb);
	return err;
	//return -ENOMEM;

#if 0

#ifdef CONFIG_MBSFS_XATTR
	sb->s_xattr = mbsFS_xattr_handlers;
#endif
#ifdef CONFIG_MBSFS_POSIX_ACL
	sb->s_flags |= MS_POSIXACL;
#endif
	uuid_gen(&sb->s_uuid);

	inode = mbsFS_get_inode(sb, NULL, S_IFDIR | sbinfo->mode, 0, VM_NORESERVE);
	if (!inode)
		goto failed;
	inode->i_uid = sbinfo->uid;
	inode->i_gid = sbinfo->gid;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		goto failed;
	return 0;

#endif
}

static struct kmem_cache *mbsfs_inode_cachep;

static struct inode *mbsfs_alloc_inode(struct super_block *sb)
{
	struct mbsfs_inode_info *info;
	info = kmem_cache_alloc(mbsfs_inode_cachep, GFP_KERNEL);
	if (!info)
		return NULL;
	return &info->vfs_inode;
}

static void mbsfs_destroy_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
	kmem_cache_free(mbsfs_inode_cachep, MBS_I(inode));
}

static void mbsfs_destroy_inode(struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		mpol_free_mbsfs_policy(&MBS_I(inode)->policy);
	call_rcu(&inode->i_rcu, mbsfs_destroy_callback);
}

static void mbsfs_init_inode(void *foo)
{
	struct mbsfs_inode_info *info = foo;
	inode_init_once(&info->vfs_inode);
}

static int mbsfs_init_inodecache(void)
{
	mbsfs_inode_cachep = kmem_cache_create("mbsFS_inode_cache",
			sizeof(struct mbsfs_inode_info),
			0, SLAB_PANIC|SLAB_ACCOUNT, mbsfs_init_inode);
	return 0;
}

static void mbsfs_destroy_inodecache(void)
{
	kmem_cache_destroy(mbsfs_inode_cachep);
}

static const struct address_space_operations mbsfs_aops = {
	//.writepage	= mbsFS_writepage,
	.set_page_dirty	= __set_page_dirty_no_writeback,
	.write_begin	= mbsfs_write_begin,
	.write_end	= mbsfs_write_end,
	//.readpage	= mbsfs_readpage,		//tNO
#ifdef CONFIG_MIGRATION
	.migratepage	= migrate_page,
#endif
	.error_remove_page = generic_error_remove_page,
};

static const struct file_operations mbsfs_file_operations = {
	.mmap		= mbsfs_mmap,
	.get_unmapped_area = mbsfs_get_unmapped_area,
	.llseek	=	mbsfs_file_llseek,
	.read_iter	= mbsfs_file_read_iter,
	.write_iter	= mbsfs_file_write_iter,
	.fsync		= noop_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= generic_file_llseek,
	//.fallocate	= mbsfs_fallocate,
	//.get_unmapped_area = mbsfs_mmu_get_unmapped_area,	//tNO
};

static const struct inode_operations mbsfs_inode_operations = {
	//.getattr	= mbsfs_getattr,
	//.setattr	= mbsfs_setattr,
	.getattr	= simple_getattr,		//tNO
	.setattr	= simple_setattr,		//tNO
#ifdef CONFIG_MBSFS_XATTR
	.listxattr	= mbsFS_listxattr,
	.set_acl	= simple_set_acl,
#endif
};

static const struct inode_operations mbsfs_dir_inode_operations = {
	.create		= mbsfs_create,
	.lookup		= simple_lookup,
	.link		= mbsfs_link,
	.unlink		= mbsfs_unlink,
	.symlink	= mbsfs_symlink,
	.mkdir		= mbsfs_mkdir,
	.rmdir		= mbsfs_rmdir,
	.mknod		= mbsfs_mknod,
	.rename		= mbsfs_rename2,
#if 0
	.tmpfile	= mbsFS_tmpfile,
#endif
#ifdef CONFIG_MBSFS_XATTR
	.listxattr	= mbsFS_listxattr,
#endif
#ifdef CONFIG_MBSFS_POSIX_ACL
	.setattr	= mbsfs_setattr,
	.set_acl	= simple_set_acl,
#endif
};

static const struct inode_operations mbsfs_special_inode_operations = {
#ifdef CONFIG_MBSFS_XATTR
	.listxattr	= mbsFS_listxattr,
#endif
#ifdef CONFIG_MBSFS_POSIX_ACL
	.setattr	= mbsfs_setattr,
	.set_acl	= simple_set_acl,
#endif
};


static const struct super_operations mbsfs_ops = {
	.statfs		= mbsfs_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= mbsfs_show_options,
	.put_super	= mbsfs_put_super,			//rNO
	//.remount_fs	= mbsFS_remount_fs,			//rNO
	.alloc_inode	= mbsfs_alloc_inode,			//rNO
	.destroy_inode	= mbsfs_destroy_inode,			//rNO
	.evict_inode	= mbsfs_evict_inode,			//rNO
#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
	.nr_cached_objects	= mbsfs_unused_huge_count,
	.free_cached_objects	= mbsfs_unused_huge_scan,
#endif
};

static const struct vm_operations_struct mbsfs_vm_ops = {
	.fault		= mbsfs_fault,
	.map_pages	= filemap_map_pages,
#ifdef CONFIG_NUMA
	.set_policy     = mbsfs_set_policy,
	.get_policy     = mbsfs_get_policy,
#endif
};
static struct dentry *mbsfs_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	struct dentry *const entry = mount_nodev(fs_type, flags, data, mbsfs_fill_super);
	if (IS_ERR(entry))
		pr_err("mbsfs mount failed\n");
	else
		pr_debug("mbsfs mounted successfully.\n");

	return entry;
}

static void mbsfs_kill_sb(struct super_block *sb)
{
	/* error produced between comments 
	   dev_t dev = sb->s_dev;
	   generic_shutdown_super(sb);
	   free_anon_bdev(dev);
	   */
	if (sb->s_root)
		d_genocide(sb->s_root);
	kill_anon_super(sb);
	pr_debug("mbsfs_kill_sb successfully finished\n");
}
static struct file_system_type mbsfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "mbsfs",
	.mount		= mbsfs_mount,
	.kill_sb	= mbsfs_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};

static int __init mbsfs_init(void)
{
	int error;

	/* don't re-init */
	if (mbsfs_inode_cachep)
		return 0;
	error = mbsfs_init_inodecache();
	if (error)
		goto out2;
	error = register_filesystem(&mbsfs_fs_type);
	if (error) {
		pr_err("Could not register mbsfs\n");
		goto out1;
	}
	pr_debug("mbsfs_init suceessed.\n");
#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
	if (has_transparent_hugepage() && mbsFS_huge > MBS_HUGE_DENY)
		MBS_SB(shm_mnt->mnt_sb)->huge = mbsFS_huge;
	else
		mbsFS_huge = 0; /* just in case it was patched */
#endif

	return 0;
out1:
	mbsfs_destroy_inodecache();
out2:
	mbsfs_mnt = ERR_PTR(error);
	return error;
}
static void __exit mbsfs_exit(void)
{
	unregister_filesystem(&mbsfs_fs_type);
	mbsfs_destroy_inodecache();
	pr_debug("mbsfs_exit successed.\n");
}

module_init(mbsfs_init);
module_exit(mbsfs_exit);

MODULE_AUTHOR("Yongseob");
MODULE_DESCRIPTION("mbsFS: memory bus-connected storage File System");
MODULE_LICENSE("GPL");
/*$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$*/
/*$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$*/
/*$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$*/
/* common code */
static const struct dentry_operations anon_ops = {
	.d_dname = simple_dname
};
#if 0
static struct file *__mbsFS_file_setup(const char *name, loff_t size,
		unsigned long flags, unsigned int i_flags)
{
	struct file *res;
	struct inode *inode;
	struct path path;
	struct super_block *sb;
	struct qstr this;

	if (IS_ERR(mbsfs_mnt))
		return ERR_CAST(mbsfs_mnt);

	if (size < 0 || size > MAX_LFS_FILESIZE)
		return ERR_PTR(-EINVAL);

	if (mbsFS_acct_size(flags, size))
		return ERR_PTR(-ENOMEM);

	res = ERR_PTR(-ENOMEM);
	this.name = name;
	this.len = strlen(name);
	this.hash = 0; /* will go */
	sb = mbsfs_mnt->mnt_sb;
	path.mnt = mntget(mbsfs_mnt);
	path.dentry = d_alloc_pseudo(sb, &this);
	if (!path.dentry)
		goto put_memory;
	d_set_d_op(path.dentry, &anon_ops);

	res = ERR_PTR(-ENOSPC);
	inode = mbsFS_get_inode(sb, NULL, S_IFREG | S_IRWXUGO, 0, flags);
	if (!inode)
		goto put_memory;

	inode->i_flags |= i_flags;
	d_instantiate(path.dentry, inode);
	inode->i_size = size;
	clear_nlink(inode);	/* It is unlinked */
	res = ERR_PTR(ramfs_nommu_expand_for_mapping(inode, size));
	if (IS_ERR(res))
		goto put_path;

	res = alloc_file(&path, FMODE_WRITE | FMODE_READ,
			&mbsfs_file_operations);
	if (IS_ERR(res))
		goto put_path;

	return res;

put_memory:
	mbsfs_unacct_size(flags, size);
put_path:
	path_put(&path);
	return res;
}

/**
 * mbsFS_kernel_file_setup - get an unlinked file living in mbsfs which must be
 * 	kernel internal.  There will be NO LSM permission checks against the
 * 	underlying inode.  So users of this interface must do LSM checks at a
 *	higher layer.  The users are the big_key and shm implementations.  LSM
 *	checks are provided at the key or shm level rather than the inode.
 * @name: name for dentry (to be seen in /proc/<pid>/maps
 * @size: size to be set for the file
 * @flags: VM_NORESERVE suppresses pre-accounting of the entire object size
 */
struct file *mbsFS_kernel_file_setup(const char *name, loff_t size, unsigned long flags)
{
	return __mbsFS_file_setup(name, size, flags, S_PRIVATE);
}

/**
 * mbsFS_file_setup - get an unlinked file living in mbsfs
 * @name: name for dentry (to be seen in /proc/<pid>/maps
 * @size: size to be set for the file
 * @flags: VM_NORESERVE suppresses pre-accounting of the entire object size
 */
struct file *mbsFS_file_setup(const char *name, loff_t size, unsigned long flags)
{
	return __mbsFS_file_setup(name, size, flags, 0);
}
//EXPORT_SYMBOL_GPL(mbsFS_file_setup);

/**
 * mbsFS_zero_setup - setup a MBS anonymous mapping
 * @vma: the vma to be mmapped is prepared by do_mmap_pgoff
 */
int mbsFS_zero_setup(struct vm_area_struct *vma)
{
	struct file *file;
	loff_t size = vma->vm_end - vma->vm_start;

	/*
	 * Cloning a new file under mmap_sem leads to a lock ordering conflict
	 * between XFS directory reading and selinux: since this file is only
	 * accessible to the user through its mapping, use S_PRIVATE flag to
	 * bypass file security, in the same way as mbsFS_kernel_file_setup().
	 */
	file = __mbsFS_file_setup("dev/zero", size, vma->vm_flags, S_PRIVATE);
	if (IS_ERR(file))
		return PTR_ERR(file);

	if (vma->vm_file)
		fput(vma->vm_file);
	vma->vm_file = file;
	vma->vm_ops = &mbsfs_vm_ops;

	return 0;
}
/**
 * mbsFS_read_mapping_page_gfp - read into page cache, using specified page allocation flags.
 * @mapping:	the page's address_space
 * @index:	the page index
 * @gfp:	the page allocator flags to use if allocating
 *
 * This behaves as a mbsfs "read_cache_page_gfp(mapping, index, gfp)",
 * with any new page allocations done using the specified allocation flags.
 * But read_cache_page_gfp() uses the ->readpage() method: which does not
 * suit mbsfs, since it may have pages in swapcache, and needs to find those
 * for itself; although drivers/gpu/drm i915 and ttm rely upon this support.
 *
 * i915_gem_object_get_pages_gtt() mixes __GFP_NORETRY | __GFP_NOWARN in
 * with the mapping_gfp_mask(), to avoid OOMing the machine unnecessarily.
 */
struct page *mbsFS_read_mapping_page_gfp(struct address_space *mapping,
		pgoff_t index, gfp_t gfp)
{
	struct inode *inode = mapping->host;
	struct page *page;
	int error;

	BUG_ON(mapping->a_ops != &mbsfs_aops);
	error = mbsfs_getpage_gfp(inode, index, &page, MBS_CACHE,
			gfp, NULL, NULL, NULL);
	if (error)
		page = ERR_PTR(error);
	else
		unlock_page(page);
	return page;
}
//EXPORT_SYMBOL_GPL(mbsFS_read_mapping_page_gfp);
#endif

/*###########################################################################*/
/*###########################################################################*/
/*###########################################################################*/
/*###########################################################################*/
/*###########################################################################*/
