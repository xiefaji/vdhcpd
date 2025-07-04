/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/include/linux/rbtree.h

  To use rbtrees you'll have to implement your own insert and search cores.
  This will avoid us to use callbacks and to drop drammatically performances.
  I know it's not the cleaner way,  but in C (not in C++) to get
  performances and genericity...

  See Documentation/rbtree.txt for documentation and samples.
*/

#ifndef __TOOLS_LINUX_PERF_RBTREE_H
#define __TOOLS_LINUX_PERF_RBTREE_H

#include <linux/kernel.h>
#include <linux/stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include "compiler.h"

//#define USE_SPIN_LOCK
#ifdef USE_SPIN_LOCK
#include <pthread.h>
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
    const typeof(((type *)0)->member) * __mptr = (ptr);	\
    (type *)((char *)__mptr - offsetof(type, member));})
#endif

struct rb_node {
    unsigned long  __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));
    /* The alignment might seem pointless, but allegedly CRIS needs it */

struct rb_root {
    struct rb_node *rb_node;
};


typedef unsigned long long key_type;
typedef void * data_type;

#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))

#define RB_ROOT	(struct rb_root) { NULL, }
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)  ((root)->rb_node == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node)  \
    ((node)->__rb_parent_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node)  \
    ((node)->__rb_parent_color = (unsigned long)(node))


extern void rb_insert_color(struct rb_node *, struct rb_root *);
extern void rb_erase(struct rb_node *, struct rb_root *);


/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_next(const struct rb_node *);
extern struct rb_node *rb_prev(const struct rb_node *);
extern struct rb_node *rb_first(const struct rb_root *);
extern struct rb_node *rb_last(const struct rb_root *);

/* Postorder iteration - always visit the parent after its children */
extern struct rb_node *rb_first_postorder(const struct rb_root *);
extern struct rb_node *rb_next_postorder(const struct rb_node *);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new_t,struct rb_root *root);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,struct rb_node **rb_link)
{
    node->__rb_parent_color = (unsigned long)parent;
    node->rb_left = node->rb_right = NULL;

    *rb_link = node;
}

#define rb_entry_safe(ptr, type, member) \
    ({ typeof(ptr) ____ptr = (ptr); \
       ____ptr ? rb_entry(____ptr, type, member) : NULL; \
    })

/*
 * Handy for checking that we are not deleting an entry that is
 * already in a list, found in block/{blk-throttle,cfq-iosched}.c,
 * probably should be moved to lib/rbtree.c...
 */
static inline void rb_erase_init(struct rb_node *n, struct rb_root *root)
{
    rb_erase(n, root);
    RB_CLEAR_NODE(n);
}

static inline void *rb_malloc(const size_t sz)
{
    void *b = malloc(sz);
    assert(b);
    return b;
}

static inline void rb_free(void *ptr)
{
    free(ptr);
}

#define RBMALLOC(sz) rb_malloc(sz)
#define RBFREE(ptr) rb_free(ptr)

#endif /* __TOOLS_LINUX_PERF_RBTREE_H */

