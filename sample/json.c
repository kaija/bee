#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
void parse_json_array()
{
    char *str;
    int len;
    char tmp[]= "{\"messages\":[\"a\",\"b\"]}";
    printf("parse\n%s\n", tmp);
    struct noly_json_array *array = noly_json_str_get_array(tmp, "messages");
    if(array) {
        int i = 0;
        for(i = 0 ; i < array->size ; i++){
            noly_json_array_get_str(array, i, &str, &len);
            printf("Item: %d   Data: %s  Len: %d\n", i, str, len);
        }
        json_array_release(array);
    }
}

void parse_json_array_obj()
{
    char tmp[]= "{\"messages\":[{\"src\":\"123456\",\"content\":\"hello\", \"sn\":\"1\"}, {\"src\":\"123457\",\"content\":\"world\"}]}";
    printf("parse\n%s\n", tmp);
    struct noly_json_array *array = noly_json_str_get_array(tmp, "messages");
    if(array) {
        int i = 0;
        for(i = 0 ; i < array->size ; i++){
            struct noly_json_obj *obj = noly_json_array_get_obj(array, i);
            if(obj){
                printf("object size %d\n", obj->size);
                printf("src : %s\n", json_object_get_string(obj->obj,"src"));
                printf("content : %s\n", json_object_get_string(obj->obj,"content"));
                free(obj);
            }
        }
        json_array_release(array);
    }
}


void parse_obj_array()
{
    char json[] = "{"
  "\"status\": {"
    "\"code\": 2222,"
    "\"message\": \"P2P get message successful\""
  "},"
  "\"ret_msg\": {"
    "\"code\": 0,"
    "\"descr\": \"\","
    "\"messages\": ["
      "{"
        "\"content\": \"AAUAAAAAADF7ImNtZCI6ImNvbm5fcmVxIiwidHlwZSI6Im1zZyIsInNyYyI6IjcwMDAwMDE2NSJ9\","
        "\"serial\": 620000088,"
        "\"src\": \"700000165\","
        "\"timestamp\": 1391879774700,"
        "\"ttl\": 8640000"
      "}"
    "],"
    "\"type\": 4,"
    "\"version\": \"1.0\""
  "}"
"}";
printf("parse:\n%s\n", json);
    char *tmp = malloc(strlen(json));
    strcpy(tmp, json);
    struct noly_json_array *ary = noly_json_str_get_array(tmp, "messages");
    if(ary){
        int i = 0;
        for(i = 0 ; i < ary->size ; i++){
            struct noly_json_obj *obj = noly_json_array_get_obj(ary, i);
            if(obj){
                printf("object size %d\n", obj->size);
                printf("src : %s\n", json_object_get_string(obj->obj,"src"));
                printf("content : %s\n", json_object_get_string(obj->obj,"content"));
                free(obj);
            }
        }
        json_array_release(ary);
    }
}

int main()
{
    parse_obj_array();
    return 0;
    parse_json_array();
    parse_json_array_obj();
    return 0;
}
