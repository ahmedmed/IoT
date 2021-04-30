#include <zephyr.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cJSON.h>

#include "msghandler.h"

/********************************************************************
 * Message Documentation
 *
 *  {
 *    'message_id'  : <message-id> - Always
 *    'device_to'   : <to device> - Optional
 *    'device_from' : <from device> - Optional
 *    'in_reply_to' : <message-id> - Optional
 *    'created'     : <message-timestamp> - Always
 *    'ttl'         : <ttl-timestamp> - Optional
 *    'frame'       : <number> - Optional
 *    'frames'      : <number> - Optional
 *    'length'      : <number> - Optional
 *    'payload'     : <data> - Always
 *  }
 *  
 ********************************************************************/
void print_message(iot_message_s * msg) {
  printf("-----------------------------------------------\n");
  printf("PAYLOAD TO MESSAGE\n");
  printf("-----------------------------------------------\n");
  printf("message-id : %s\n", msg->message_id);

  if (strlen(msg->device_to) > 0) {
    printf("device-to  : %s\n", msg->device_to);
  }
  if (strlen(msg->device_from) > 0) {
    printf("device-from: %s\n", msg->device_from);
  }
  if (strlen(msg->in_reply_to) > 0) {
    printf("in-reply-to: %s\n", msg->in_reply_to);
  }
  printf("created    : %d\n", (int)msg->created);

  if (msg->ttl > 0) {
    printf("ttl        : %d\n", (int)msg->ttl);
  }

  printf("frame      : %d\n", msg->frame);
  printf("frames     : %d\n", msg->frames);
  printf("length     : %d\n", msg->length);
  printf("-----------------------------------------------\n");
}

void print_message_content(iot_message_content_s* content) {
  printf("-----------------------------------------------\n");
  printf("PAYLOAD TO MESSAGE->CONTENT\n");
  printf("-----------------------------------------------\n");
  printf("object: %i\n", content->object);

  if (strlen(content->instance) > 0) {
    printf("instance: %s\n", content->instance);
  }

  printf("method: %i\n", content->method);
  printf("-----------------------------------------------\n"); 
}

time_t from_iso8601_utc(const char* dateStr)
{
    struct tm t;
    int success = sscanf(dateStr, "%d-%d-%dT%d:%dZ", /* */
                         &t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min);
    if (success != 5) {
        return 0;
    }

    /* compensate expected ranges */
    t.tm_year = t.tm_year - 1900;
    t.tm_mon = t.tm_mon - 1;
    t.tm_sec = 0;
    t.tm_wday = 0;
    t.tm_yday = 0;
    t.tm_isdst = 0;

    time_t localTime = mktime(&t);
    time_t utcTime = localTime; // - timezone;

    return utcTime;
}

int from_utc_iso8601(struct tm * t, char * date, int size) {
  return snprintf(date, size, "%d-%02d-%02dT%02d:%02dZ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min);
}


int static msghandler_get_json_string(cJSON * root, char * parameter, char * value, int len) {
  int ret = 0;

  cJSON *data = cJSON_GetObjectItemCaseSensitive(root, parameter);

  if (cJSON_IsString(data) && (data->valuestring != NULL)) {
    strncpy(value, data->valuestring, len);
     
    ret = 1;
  }
  return ret;
}

int msghandler_get_json_number(cJSON * root, char * parameter, double * value) {
  int ret = 0;

  cJSON *data = cJSON_GetObjectItemCaseSensitive(root, parameter);

  if (cJSON_IsNumber(data)) {
    *value = data->valuedouble;
    
    ret = 1;
  }
  return ret;
}

int msghandler_get_json_int(cJSON * root, char * parameter, int * value) {
  int ret = 0;

  cJSON *data = cJSON_GetObjectItemCaseSensitive(root, parameter);

  if (cJSON_IsNumber(data)) {
    *value = data->valueint;

    ret = 1;
  }
  return ret;
}


iot_status_t msghandler_parse_content_values(cJSON * root, iot_message_content_s* content) {
  iot_status_t retval = IOT_SUCCESS;

  cJSON *values = cJSON_GetObjectItemCaseSensitive(root, "values");
  if (cJSON_IsObject(values)) {

  }
  else {
    printf("Values is not an object!\n");
  }
  return retval;
}

iot_status_t msghandler_payload_to_content(const u8_t *payload, iot_message_content_s* content) {

  iot_status_t retval = IOT_MSG_CONTENT_PARAMETER_MISSING;
  int result = 0;

  cJSON *root = cJSON_Parse(payload);
  if (root != NULL) {
    result = msghandler_get_json_int(root, "object", (int*)&content->object);
    if (result) {
      msghandler_get_json_string(root, "instance", content->instance, 32);

      result = msghandler_get_json_int(root, "method", (int*)&content->method);
      if (result) {
        retval = msghandler_parse_content_values(root, content);
      }
    }
    print_message_content(content);
  }
  else {
    retval = IOT_MSG_PARSE_ERROR;
  }
  cJSON_Delete(root);

  return retval;  
}

iot_status_t msghandler_content_to_payload(iot_message_content_s* content, char** payload) {
  iot_status_t retval = IOT_SUCCESS;

  cJSON *root = cJSON_CreateObject();
  if (root != NULL) {
    char value[16] = {0};

    sprintf(value, "%d", content->object);
    cJSON_AddStringToObject(root, "object", value);
    //cJSON_AddNumberToObject(root, "object", (double)content->object);
    
    if (strlen(content->instance) > 0) {
      cJSON_AddStringToObject(root, "instance", content->instance);
    }
    sprintf(value, "%d", content->method);
    cJSON_AddStringToObject(root, "method", value);
    //cJSON_AddNumberToObject(root, "method",  (double)content->method);
    

    *payload = cJSON_Print(root);
    cJSON_Delete(root);

    if (*payload == NULL) {
      printf("Faild to print content\n");
    }
    else {
      printf("%s\n", *payload);
    }
  }
  else {
    retval = IOT_MSG_PARSE_ERROR;
  }
  

  return retval;  
}

iot_status_t msghandler_payload_to_msg(const u8_t *payload, iot_message_s* msg, char** content) {
  iot_status_t retval = IOT_MSG_HEADER_PARAMETER_MISSING;
  int result = 0;

  cJSON *root = cJSON_Parse(payload);
  if (root != NULL) {
    unsigned char tmp[32] = {0};

    result = msghandler_get_json_string(root, "message_id", msg->message_id, 40);  //Always
    if (result) {
      msghandler_get_json_string(root, "device_to", msg->device_to, 32);           //Optional
      msghandler_get_json_string(root, "device_from", msg->device_from, 32);       //Optional
      msghandler_get_json_string(root, "in_reply_to", msg->in_reply_to, 40);       //Optional

      result = msghandler_get_json_string(root, "created", tmp, 32);               //Always
      if (result) {
        msg->created = from_iso8601_utc(tmp);

        result = msghandler_get_json_string(root, "ttl", tmp, 32);                 //Optional
        if (result) {
          msg->ttl = from_iso8601_utc(tmp);
        }
        
        result = msghandler_get_json_int(root, "frame", (int*)&msg->frame);        //Optional
        if (!result) {
          msg->frame = 1;
        }

        result = msghandler_get_json_int(root, "frames", (int*)&msg->frames);      //Optional
        if (!result) {
          msg->frames = 1;
        }

        result = msghandler_get_json_int(root, "length", (int*)&msg->length);      //Optional
        if (!result) {  
          //TODO - calculate length?
          msg->length = 0;
        }

        //Content 
        *content = malloc(msg->length+1);
        if (*content != NULL) {
          memset(*content, 0, msg->length+1);

          result = msghandler_get_json_string(root, "data", *content, msg->length); //Always 
          if (result) {
            retval = IOT_SUCCESS;
          }
        }
        /*
        char * msgdata = malloc(msg->length+1);
        if (msgdata != NULL) {
          memset(msgdata, 0, msg->length+1);

          result = msghandler_get_json_string(root, "data", msgdata, msg->length); //Always
          if(result) {
            retval = msghandler_parse_content(msgdata, msg);
          }
          free(msgdata);
          msgdata = NULL;
        }*/
     
      }
      print_message(msg);
      cJSON_Delete(root);
    } 
  }
  else {
    retval = IOT_MSG_PARSE_ERROR;
  }

  return retval;
}


iot_status_t msghandler_msg_to_payload(iot_message_s* msg, char* data, char** payload) {
  iot_status_t retval = IOT_SUCCESS;

  cJSON *root = cJSON_CreateObject();
  if (root != NULL) {
    struct tm* local;
    char date[32] = {0};
    char value[16] = {0};

    cJSON_AddStringToObject(root, "message_id", msg->message_id);

    if (strlen(msg->device_to) > 0) {
      cJSON_AddStringToObject(root, "device_to", msg->device_to);
    }
    if (strlen(msg->device_from) > 0) {
      cJSON_AddStringToObject(root, "device_from", msg->device_from);
    }
    if (strlen(msg->in_reply_to) > 0) {
      cJSON_AddStringToObject(root, "in_reply_to", msg->in_reply_to);
    }

    local = localtime(&msg->created);
    from_utc_iso8601(local, (char*)date, 32);
    cJSON_AddStringToObject(root, "created", (char*)date);
    
    if (msg->ttl) {
      memset(date, 0, 32);
      local = localtime(&msg->ttl);
      from_utc_iso8601(local, (char*)date, 32);
      cJSON_AddStringToObject(root, "ttl", (char*)date);
    }
    sprintf(value, "%d", msg->frame);
    cJSON_AddStringToObject(root, "frame", value);
    sprintf(value, "%d", msg->frames);
    cJSON_AddStringToObject(root, "frames", value);
    sprintf(value, "%d", msg->length);
    cJSON_AddStringToObject(root, "length", value);

    //cJSON_AddNumberToObject(root, "frame", msg->frame);
    //cJSON_AddNumberToObject(root, "frames", msg->frames);
    //cJSON_AddNumberToObject(root, "length", msg->length);

    cJSON_AddStringToObject(root, "data", data);

    *payload = cJSON_Print(root);
  }
  else {
    retval = IOT_MSG_PARSE_ERROR;
  }
  cJSON_Delete(root);

  return retval;
}



