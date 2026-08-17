# REV CHALL

```c
struct klist_head {
    struct node *head;      // First node in the linked list
    uint64_t max_nodes;     // Maximum number of nodes allowed
    uint64_t node_count;    // Current number of allocated nodes
};

struct node {
    char data[0x60];
    struct node *next;
    size_t data_len;        // strnlen(data, 0x60)
};
```

## CMD_CREATE_NODE (`0x40606B00`)

```c
if (head->node_count < head->max_nodes) {

    // Read 0x60 bytes from userland
    copy_from_user(buf, arg, 0x60);
    node = kmalloc(...);
    ...
    node->next = NULL;
    ...
    node->data_len = strnlen(node->data, 0x60);

    if (head->head == NULL) {
        // First node
        head->head = node;
    } else {
        // Append to the end of the linked list
        curr = head->head;

        while (curr->next)
            curr = curr->next;

        curr->next = node;
    }

    head->node_count++;
    mutex_unlock();
}
```

## CMD_WRITE_TO_NODE (`0x40686B01`)

```c
struct request {
    uint32_t index;
    uint32_t length;
    char data[0x60];
};

copy_from_user(&req, arg, 0x68);

// Maximum write size is 0x60 bytes.
if (req.length <= 0x60) {
    ....
    curr = head->head;

    // Traverse to the requested node.
    for (i = 0; curr && i < req.index; i++)
        curr = curr->next;

    if (curr) {
        /*
         * The driver only checks that data_len <= 0x5f.
         * It never verifies that data_len + length stays
         * within the 0x60-byte data buffer.
         */
        if (curr->data_len <= 0x5f) {
            memcpy(curr->data + curr->data_len,
                   req.data,
                   req.length);

            /*
             * Vulnerability:
             *
             * If data_len + length > 0x60, memcpy()
             * overflows past the end of data[],
             * corrupting adjacent fields such as:
             *
             *   curr->next
             *   curr->data_len
             */
        }
    }
}
```
