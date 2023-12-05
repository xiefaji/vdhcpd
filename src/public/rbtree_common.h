#ifndef _rbtree_common_h
#define _rbtree_common_h

#include "share/defines.h"
#include "share/array/trashqueue.h"
#include "share/rbtree/key_elem.h"
#include "share/rbtree/set_elem.h"
#include "share/rbtree/tag_elem.h"


ALWAYS_INLINE void key_tree_nodes_release(struct key_tree *key_tree, void (*release_callback)(void *p))
{
    struct key_node *key_node = key_first(key_tree);
    while (key_node && key_node->data) {
        if (release_callback) release_callback(key_node->data);
        key_node = key_rberase(key_tree, key_node);
    }
}

ALWAYS_INLINE void key_tree_nodes_recycle(struct key_tree *key_tree, trash_queue_t *pRecycleTrash, void (*recycle_callback)(void *p, trash_queue_t *pRecycleTrash))
{
    struct key_node *key_node = key_first(key_tree);
    while (key_node && key_node->data) {
        if (recycle_callback) recycle_callback(key_node->data, pRecycleTrash);
        key_node = key_rberase_EX(key_tree, key_node, pRecycleTrash, trash_queue_enqueue2);
    }
}

ALWAYS_INLINE void set_tree_nodes_release(struct set_tree *set_tree, void (*release_callback)(void *p))
{
    struct set_node *set_node = set_first(set_tree);
    while (set_node && set_node->data) {
        if (release_callback) release_callback(set_node->data);
        set_node = set_rberase(set_tree, set_node);
    }
}

ALWAYS_INLINE void set_tree_nodes_recycle(struct set_tree *set_tree, trash_queue_t *pRecycleTrash, void (*recycle_callback)(void *p, trash_queue_t *pRecycleTrash))
{
    struct set_node *set_node = set_first(set_tree);
    while (set_node && set_node->data) {
        if (recycle_callback) recycle_callback(set_node->data, pRecycleTrash);
        set_node = set_rberase_EX(set_tree, set_node, pRecycleTrash, trash_queue_enqueue2);
    }
}

ALWAYS_INLINE void tag_tree_nodes_release(struct tag_tree *tag_tree, void (*release_callback)(void *p))
{
    struct tag_node *tag_node = tag_first(tag_tree);
    while (tag_node && tag_node->data) {
        if (release_callback) release_callback(tag_node->data);
        tag_node = tag_rberase(tag_tree, tag_node);
    }
}

ALWAYS_INLINE void tag_tree_nodes_recycle(struct tag_tree *tag_tree, trash_queue_t *pRecycleTrash, void (*recycle_callback)(void *p, trash_queue_t *pRecycleTrash))
{
    struct tag_node *tag_node = tag_first(tag_tree);
    while (tag_node && tag_node->data) {
        if (recycle_callback) recycle_callback(tag_node->data, pRecycleTrash);
        tag_node = tag_rberase_EX(tag_tree, tag_node, pRecycleTrash, trash_queue_enqueue2);
    }
}

#endif
