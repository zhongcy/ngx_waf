#ifndef NGX_HTTP_WAF_MODULE_IP_TRIE_h
#define NGX_HTTP_WAF_MODULE_IP_TRIE_h

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>

static ngx_int_t ip_trie_init(ip_trie_t** trie, ngx_pool_t* memory_pool, int ip_type);

static ngx_int_t ip_trie_add(ip_trie_t* trie, inx_addr_t* inx_addr, uint32_t suffix_num, u_char* text);

static ngx_int_t ip_trie_find(ip_trie_t* trie, inx_addr_t* inx_addr, ip_trie_node_t** ip_trie_node);

// static ngx_int_t ip_trie_delete(ip_trie_t* trie, inx_addr_t* inx_addr);


static ngx_int_t ip_trie_init(ip_trie_t** trie, ngx_pool_t* memory_pool, int ip_type) {
    if (trie == NULL) {
        return FAIL;
    }

    *trie = (ip_trie_t*)ngx_pcalloc(memory_pool, sizeof(ip_trie_t));
    if (*trie == NULL) {
        return FAIL;
    }

    (*trie)->ip_type = ip_type;
    (*trie)->memory_pool = memory_pool;
    (*trie)->root = (ip_trie_node_t*)ngx_pcalloc(memory_pool, sizeof(ip_trie_node_t));
    (*trie)->size = 0;

    if ((*trie)->root == NULL) {
        return FAIL;
    }

    return SUCCESS;
}

static ngx_int_t ip_trie_add(ip_trie_t* trie, inx_addr_t* inx_addr, uint32_t suffix_num, u_char* text) {
    if (trie == NULL || inx_addr == NULL) {
        return FAIL;
    }

    ip_trie_node_t* new_node = NULL;

    if (ip_trie_find(trie, inx_addr, &new_node) == SUCCESS) {
        return FAIL;
    }

    new_node = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
    if (new_node == NULL) {
        return FAIL;
    }
    
    new_node->is_ip = TRUE;
    if (trie->ip_type == AF_INET) {
        memcpy(new_node->text, text, 32);
    } else if (trie->ip_type == AF_INET6) {
        memcpy(new_node->text, text, 64);
    }

    ip_trie_node_t* prev_node = trie->root;
    ip_trie_node_t* cur_node = trie->root;
    uint32_t bit_index = 0;
    int uint8_index = 0;

    if (trie->ip_type == AF_INET) {
        uint8_t u8_addr[4];
        u8_addr[0] = (uint8_t)(inx_addr->ipv4.s_addr & 0x000000ff);
        u8_addr[1] = (uint8_t)((inx_addr->ipv4.s_addr & 0x0000ff00) >> 8);
        u8_addr[2] = (uint8_t)((inx_addr->ipv4.s_addr & 0x00ff0000) >> 16);
        u8_addr[3] = (uint8_t)((inx_addr->ipv4.s_addr & 0xff000000) >> 24);

        while (bit_index < suffix_num - 1) {
            uint8_index = bit_index / 8;
            prev_node = cur_node;
            if (CHECK_FLAG(u8_addr[uint8_index], 0x80 >> (bit_index % 8)) == TRUE) {
                if (cur_node->left == NULL) {
                    cur_node->left = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
                    if (cur_node->left == NULL) {
                        return FAIL;
                    }
                }
                cur_node = cur_node->left;
            } else {
                if (cur_node->right == NULL) {
                    cur_node->right = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
                    if (cur_node->right == NULL) {
                        return FAIL;
                    }
                }
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
        uint8_index = bit_index / 8;
        if (CHECK_FLAG(u8_addr[uint8_index], 0x80 >> (bit_index % 8)) == TRUE) {
            prev_node->left = new_node;
        } else {
            prev_node->right = new_node;
        }
        
    } else if (trie->ip_type == AF_INET6) {
        while (bit_index < suffix_num - 1) {
            uint8_index = bit_index / 8;
            prev_node = cur_node;
            if (CHECK_FLAG(inx_addr->ipv6.__in6_u.__u6_addr8[uint8_index], 0x80 >> (bit_index % 8)) == TRUE) {
                if (cur_node->left == NULL) {
                    cur_node->left = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
                    if (cur_node->left == NULL) {
                        return FAIL;
                    }
                }
                cur_node = cur_node->left;
            } else {
                if (cur_node->right == NULL) {
                    cur_node->right = (ip_trie_node_t*)ngx_pcalloc(trie->memory_pool, sizeof(ip_trie_node_t));
                    if (cur_node->right == NULL) {
                        return FAIL;
                    }
                }
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
        uint8_index = bit_index / 8;
        if (CHECK_FLAG(inx_addr->ipv6.__in6_u.__u6_addr8[uint8_index], 0x80 >> (bit_index % 8)) == TRUE) {
            prev_node->left = new_node;
        } else {
            prev_node->right = new_node;
        }
    }

    return SUCCESS;
}

static ngx_int_t ip_trie_find(ip_trie_t* trie, inx_addr_t* inx_addr, ip_trie_node_t** ip_trie_node) {
    if (trie == NULL || inx_addr == NULL || ip_trie_node ==NULL) {
        return FAIL;
    }

    *ip_trie_node = NULL;

    ip_trie_node_t* cur_node = trie->root;
    ngx_int_t isFound = FALSE;
    uint32_t bit_index = 0;

    if (trie->ip_type == AF_INET) {
        uint8_t u8_addr[4];
        u8_addr[0] = (uint8_t)(inx_addr->ipv4.s_addr & 0x000000ff);
        u8_addr[1] = (uint8_t)((inx_addr->ipv4.s_addr & 0x0000ff00) >> 8);
        u8_addr[2] = (uint8_t)((inx_addr->ipv4.s_addr & 0x00ff0000) >> 16);
        u8_addr[3] = (uint8_t)((inx_addr->ipv4.s_addr & 0xff000000) >> 24);

        while (bit_index < 32 && cur_node != NULL && cur_node->is_ip != TRUE) {
            int uint8_index = bit_index / 8;
            if (CHECK_FLAG(u8_addr[uint8_index], 0x80 >> (bit_index % 8)) == TRUE) {
                cur_node = cur_node->left;
            } else {
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
        
    } else if (trie->ip_type == AF_INET6) {
        while (bit_index < 128 && cur_node != NULL && cur_node->is_ip != TRUE) {
            int uint8_index = bit_index / 8;
            if (CHECK_FLAG(inx_addr->ipv6.__in6_u.__u6_addr8[uint8_index], 0x80 >> (bit_index % 8)) == TRUE) {
                cur_node = cur_node->left;
            } else {
                cur_node = cur_node->right;
            }
            ++bit_index;
        }
    }

    if (cur_node != NULL && cur_node->is_ip == TRUE) {
        isFound = TRUE;
        *ip_trie_node = cur_node;
    }

    return isFound;
}

#endif