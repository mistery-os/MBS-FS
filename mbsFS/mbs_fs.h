/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MBS_FS_H
#define __MBS_FS_H

#include <linux/file.h>
#include <linux/swap.h>
#include <linux/mempolicy.h>
#include <linux/pagemap.h>
#include <linux/percpu_counter.h>
#include <linux/xattr.h>

struct mbsfs_mount_opts {
	umode_t mode;
};

struct mbsfs_fs_info {
	struct mbsfs_mount_opts mount_opts;
};

enum {
	Opt_mode,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

#define MBSFS_DEFAULT_MODE	0755

/* inode in-kernel data */

struct mbsfs_inode_info {
	spinlock_t		lock;
	unsigned int		seals;		/* mbsFS seals */
	unsigned long		flags;
	unsigned long		alloced;	/* data pages alloced to file */
	//unsigned long		swapped;	/* subtotal assigned to swap */
	//struct list_head      shrinklist;     /* shrinkable hpage inodes */
	//struct list_head	swaplist;	/* chain of maybes on swap */
	//struct shared_policy	policy;		/* NUSA memory alloc policy */
	struct mbsfs_policy	policy;		/* NUSA memory alloc policy */
	struct simple_xattrs	xattrs;		/* list of xattrs */
	struct inode		vfs_inode;
};

static inline struct mbsfs_inode_info *MBS_I(struct inode *inode)
{
	return container_of(inode, struct mbsfs_inode_info, vfs_inode);
}

struct mbsfs_sb_info {
	unsigned long max_blocks;   /* How many blocks are allowed */
	struct percpu_counter used_blocks;  /* How many are allocated */
	unsigned long max_inodes;   /* How many inodes are allowed */
	unsigned long free_inodes;  /* How many are left for allocation */
	spinlock_t stat_lock;	    /* Serialize mbsFS_sb_info changes */
	umode_t mode;		    /* Mount mode for root directory */
	unsigned char huge;	    /* Whether to try for hugepages */
	kuid_t uid;		    /* Mount uid for root directory */
	kgid_t gid;		    /* Mount gid for root directory */
	struct mempolicy *mpol;     /* default memory policy for mappings */
	//spinlock_t shrinklist_lock;   /* Protects shrinklist */
	//struct list_head shrinklist;  /* List of shinkable inodes */
	//unsigned long shrinklist_len; /* Length of shrinklist */
};

static inline struct mbsfs_sb_info *MBS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

//extern int mbsFS_init(void);
//extern int mbsFS_fill_super(struct super_block *sb, void *data, int silent);
extern struct file *mbsFS_file_setup(const char *name,
		loff_t size, unsigned long flags);
//extern struct file *mbsFS_kernel_file_setup(const char *name, loff_t size,
//					    unsigned long flags);
//extern int mbsFS_zero_setup(struct vm_area_struct *);
//extern unsigned long mbsFS_get_unmapped_area(struct file *, unsigned long addr,
//		unsigned long len, unsigned long pgoff, unsigned long flags);
//extern int mbsFS_lock(struct file *file, int lock, struct user_struct *user);
//#ifdef CONFIG_MBS
//extern bool mbsFS_mapping(struct address_space *mapping);
//#else
//static inline bool mbsFS_mapping(struct address_space *mapping)
//{
//	return false;
//}
//#endif /* CONFIG_MBS */
//extern void mbsFS_unlock_mapping(struct address_space *mapping);
//extern struct page *mbsFS_read_mapping_page_gfp(struct address_space *mapping,
//					pgoff_t index, gfp_t gfp_mask);
//extern void mbsFS_truncate_range(struct inode *inode, loff_t start, loff_t end);
//extern int mbsFS_unuse(swp_entry_t entry, struct page *page);
//
//extern unsigned long mbsFS_swap_usage(struct vm_area_struct *vma);
//extern unsigned long mbsFS_partial_swap_usage(struct address_space *mapping,
//						pgoff_t start, pgoff_t end);

/* Flag allocation requirements to mbsFS_getpage */
enum mbs_type {
	MBS_READ,	/* don't exceed i_size, don't allocate page */
	MBS_CACHE,	/* don't exceed i_size, may allocate page */
	MBS_NOHUGE,	/* like MBS_CACHE, but no huge pages */
	MBS_HUGE,	/* like MBS_CACHE, huge pages preferred */
	MBS_WRITE,	/* may exceed i_size, may allocate !Uptodate page */
	MBS_FALLOC,	/* like MBS_WRITE, but make existing page Uptodate */
};

#if 0
extern int mbsFS_getpage(struct inode *inode, pgoff_t index,
		struct page **pagep, enum mbs_type sgp);

static inline struct page *mbsFS_read_mapping_page(
		struct address_space *mapping, pgoff_t index)
{
	return mbsFS_read_mapping_page_gfp(mapping, index,
			mapping_gfp_mask(mapping));
}

static inline bool mbsFS_file(struct file *file)
{
	if (!IS_ENABLED(CONFIG_MBS))
		return false;
	if (!file || !file->f_mapping)
		return false;
	return mbsFS_mapping(file->f_mapping);
}

extern bool mbsFS_charge(struct inode *inode, long pages);
extern void mbsFS_uncharge(struct inode *inode, long pages);


extern int mbsFS_add_seals(struct file *file, unsigned int seals);
extern int mbsFS_get_seals(struct file *file);
extern long mbsFS_fcntl(struct file *file, unsigned int cmd, unsigned long arg);


static inline long mbsFS_fcntl(struct file *f, unsigned int c, unsigned long a)
{
	return -EINVAL;
}

//#endif

//#ifdef CONFIG_TRANSPARENT_HUGE_PAGECACHE
extern bool mbsFS_huge_enabled(struct vm_area_struct *vma);
//#else
static inline bool mbsFS_huge_enabled(struct vm_area_struct *vma)
{
	return false;
}
//#endif

//#ifdef CONFIG_MBS
extern int mbsFS_mcopy_atomic_pte(struct mm_struct *dst_mm, pmd_t *dst_pmd,
		struct vm_area_struct *dst_vma,
		unsigned long dst_addr,
		unsigned long src_addr,
		struct page **pagep);
extern int mbsFS_mfill_zeropage_pte(struct mm_struct *dst_mm,
		pmd_t *dst_pmd,
		struct vm_area_struct *dst_vma,
		unsigned long dst_addr);
// #else
#define mbsFS_mcopy_atomic_pte(dst_mm, dst_pte, dst_vma, dst_addr, \
		src_addr, pagep)        ({ BUG(); 0; })
#define mbsFS_mfill_zeropage_pte(dst_mm, dst_pmd, dst_vma, \
		dst_addr)      ({ BUG(); 0; })
// #endif
#endif
//<<<2018.06.25 Yongseob
#if 0
extern void prep_transhuge_page(struct page *page);
extern int split_huge_page_to_list(struct page *page, struct list_head *list);
extern void mem_cgroup_migrate(struct page *oldpage, struct page *newpage);
extern struct static_key_false memcg_sockets_enabled_key;
extern int mem_cgroup_try_charge_swap(struct page *page, swp_entry_t entry);
extern void page_add_file_rmap(struct page *page, bool compound);
extern swp_entry_t get_swap_page(struct page *page);
extern int add_to_swap_cache(struct page *page, swp_entry_t entry, gfp_t gfp_mask);
extern void delete_from_swap_cache(struct page *page);
extern struct page *swapin_readahead(swp_entry_t entry, gfp_t gfp_mask,
		struct vm_area_struct *vma, unsigned long addr);
extern atomic_long_t nr_swap_pages;
extern long total_swap_pages;
extern void swap_free(swp_entry_t entry);
extern void put_swap_page(struct page *page, swp_entry_t entry);
extern int page_swapcount(struct page *page);
extern int free_swap_and_cache(swp_entry_t entry);
extern void swap_shmem_alloc(swp_entry_t entry);
extern void swap_shmem_alloc(swp_entry_t entry);
extern void swap_mbs_alloc(swp_entry_t entry);
extern int truncate_inode_page(struct address_space *mapping, struct page *page);
extern void check_move_unevictable_pages(struct page **pages, int nr_pages);
#endif
#endif
