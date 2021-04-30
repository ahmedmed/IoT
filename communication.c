#include <zephyr.h>
#include <errno.h>
#include <stdio.h>
#include <net/coap.h>
#include <net/socket.h>

#include "communication.h"
#include "msghandler.h"

#define COAP_VERSION 1
#define NUMBER_OF_CONNECTIONS 1

struct connection_settings_s {
  int nbiot_sock;
  struct pollfd fds;
  u16_t next_token;
  u8_t coap_buf[1024];
};

struct connection_settings_s connections[NUMBER_OF_CONNECTIONS] = {0};

static int handleHash[NUMBER_OF_CONNECTIONS] = {0};

iot_status_t communication_wait(int handle, int wait) {
  int ret = poll(&connections[handle].fds, 1, wait);

  if (ret < 0) {
    printf("poll error: %d\n", errno);
    return IOT_UNKNOWN_ERROR;
  }

  if (ret == 0) {
    /* Timeout. */
    return IOT_TIMEOUT;
  }

  if ((connections[handle].fds.revents & POLLERR) == POLLERR) {
    printf("wait: POLLERR\n");
    return IOT_IO_ERROR;
  }

  if ((connections[handle].fds.revents & POLLNVAL) == POLLNVAL) {
    printf("wait: POLLNVAL\n");
    return IOT_BAD_FILE_ERROR;
  }

  if ((connections[handle].fds.revents & POLLIN) != POLLIN) {
    return IOT_TIMEOUT;
  }
  return IOT_SUCCESS;
}

iot_status_t communication_coap_open(int * handle) {
  int err;
  int i;
  int h = -1;

  for (i=0; i<NUMBER_OF_CONNECTIONS; i++) {
    if (handleHash[i] == 0) {
      h = i;
      handleHash[i] = 1;
      break;
    }
  }
  //printf("handle = %d\n", h);
  
  if (h < 0) {
    return IOT_CONNECTION_ERROR;
  }
 
  *handle = h;

  connections[*handle].nbiot_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  //printf("Test %d\n", connections[*handle].nbiot_sock);
  if (connections[h].nbiot_sock < 0) {
    printf("Error opening nbiot_socket: %d\n", errno);
    return IOT_SOCKET_ERROR;
  } 
  
  static struct sockaddr_in remote_addr = {
    sin_family: AF_INET,
    sin_port:   htons(NBIOT_SERVER_PORT),
  };
  net_addr_pton(AF_INET, NBIOT_SERVER_HOST, &remote_addr.sin_addr);

  err = connect(connections[*handle].nbiot_sock, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in));
  if (err < 0) {
    printf("COAP Connect to %s on port %d failed : %d\n", NBIOT_SERVER_HOST, NBIOT_SERVER_PORT, errno);
    return IOT_CONNECT_ERROR;
  }
  
  // Initialize FDS, for poll. 
  connections[*handle].fds.fd = connections[*handle].nbiot_sock;
  connections[*handle].fds.events = POLLIN;

  // Randomize token. 
  connections[*handle].next_token = sys_rand32_get();

  return IOT_SUCCESS;
}

void communication_coap_close(int handle) {
  close(connections[handle].nbiot_sock);

  connections[handle].nbiot_sock= 0;
  connections[handle].fds.fd= 0;
  connections[handle].fds.events= 0;
  connections[handle].next_token= 0;

  memset(connections[handle].coap_buf, 0, 1024);

  handleHash[handle] = 0;  
}


iot_status_t communication_coap_get(iot_message_s* msg, s64_t wait) {
  iot_status_t ret;
  int err;
  int received;
  struct coap_packet request;

  int loop;
  int number_of_msg = 0;

  char* content_data = NULL;
  int content_data_length = 0;

  int handle;

  ret = communication_coap_open(&handle);
  if (ret != IOT_SUCCESS) {
    return IOT_SOCKET_ERROR;
  }  

  connections[handle].next_token++;

  do {
    loop = 0;

    err = coap_packet_init(&request, connections[handle].coap_buf, sizeof(connections[handle].coap_buf),
            COAP_VERSION, COAP_TYPE_NON_CON,
		        sizeof(connections[handle].next_token), (u8_t *)&connections[handle].next_token,
		        COAP_METHOD_GET, coap_next_id());
    
    if (err >= 0) {
      err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH, (u8_t *)NBIOT_RESOURCE, strlen(NBIOT_RESOURCE));
	    if (err >= 0) {
        err = send(connections[handle].nbiot_sock, request.data, request.offset, 0);
        if (err >= 0) {
          ret = communication_wait(handle, wait);
          if (ret == IOT_SUCCESS) {
            received = recv(connections[handle].nbiot_sock, connections[handle].coap_buf, sizeof(connections[handle].coap_buf), MSG_DONTWAIT);
            if (received > 0) {
              struct coap_packet reply;
              const u8_t *payload;
              u16_t payload_len;
              u8_t token[8];
	            u16_t token_len;

              err = coap_packet_parse(&reply, connections[handle].coap_buf, received, NULL, 0);
              if (err >= 0) {
                payload = coap_packet_get_payload(&reply, &payload_len);
	              token_len = coap_header_get_token(&reply, token);
                
                if (token_len == sizeof(connections[handle].next_token)  && !memcmp(&connections[handle].next_token, token, sizeof(connections[handle].next_token))) {
                  iot_message_s message = {0};
                  char *content_ptr = NULL;
                  
                  ret = msghandler_payload_to_msg(payload,  &message, &content_ptr);
                  if (ret == IOT_SUCCESS) {
                    number_of_msg++;

                    if (number_of_msg == 1) {
                      memcpy(msg->message_id, message.message_id, strlen(message.message_id));

                      if (strlen(message.device_to) > 0) {
                        memcpy(msg->device_to, message.device_to, strlen(message.device_to));
                      }
                      if (strlen(message.device_from) > 0) {
                        memcpy(msg->device_from, message.device_from, strlen(message.device_from));
                      }
                      if (strlen(message.device_from) > 0) {
                        memcpy(msg->device_from, message.device_from, strlen(message.device_from));
                      }
                      
                      msg->created = message.created;
                      msg->ttl = message.ttl;

                      msg->frame = number_of_msg;
                      msg->frames = message.frames;
                      msg->length += message.length;

                      content_data = malloc(msg->frames * msg->length);
                    }

                    if ((message.frames > number_of_msg)) {
                      if (!strcmp(message.message_id, msg->message_id)) {
                        loop = 1;
                      }
                      else {
                        ret = IOT_UNKNOWN_ERROR;
                      }
                    }

                    if (content_ptr) {
                      if (content_data) {
                        memcpy(content_data + content_data_length, content_ptr, message.length);
                        content_data_length += message.length;
                      }
                      else {
                        ret = IOT_MEMORY_ERROR;
                      }
                      free(content_ptr);
                    }
                  }
                }
                else {
                  printf("Invalid token received: 0x%02x%02x\n",token[1], token[0]);
		              return 0;
	              }
              }
	            else {
                printf("Malformed response received: %d\n", err);
                ret = IOT_COAP_ENCODE_ERROR;
	            }
            }
            else {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("socket EAGAIN\n");
                ret = IOT_TIMEOUT;
              }
              else {
                printf("Socket error, exit...\n");
                ret = IOT_SOCKET_ERROR;
              }
            }
          }
        }
        else {
          printf("Failed to send CoAP request, %d\n", errno);
          ret = IOT_SEND_ERROR;
        }
      }
      else {
        printf("Failed to encode CoAP option, %d\n", err);
        ret = IOT_COAP_ENCODE_ERROR;
      }
    }
    else {
       printf("Failed to create CoAP request, %d\n", err);
      ret = IOT_COAP_REQUEST_ERROR;
    }
  } while (loop && ret == IOT_SUCCESS);

  communication_coap_close(handle);
  
  if (ret == IOT_SUCCESS) {
    ret =  msghandler_payload_to_content(content_data, &msg->content);
  }

  if (content_data) {
    free(content_data);
  }

  return ret;
}

iot_status_t communication_coap_post(iot_message_s * msg) {
  iot_status_t retval;
  int err;
  struct coap_packet request;
  u8_t payload[1032];

  int loop = 0;
  char *content_ptr = NULL;

  int handle;

  retval = communication_coap_open(&handle);
  if (retval != IOT_SUCCESS) {
    return IOT_SOCKET_ERROR;
  }  


  retval = msghandler_content_to_payload(&msg->content, &content_ptr);
  if (retval == IOT_SUCCESS) {
    int data_length;
    int frames;
    int i = 1;
    int length = 0;

    int content_length = strlen(content_ptr);
    
    char *msg_ptr = NULL;

    frames = (content_length / 900) + 1;

    do {
      char data[901] = {0};
      if (frames > i) {
        data_length = 900;
        length += 900;
      }
      else {
        data_length = content_length - ((i-1)*900);
      }

      memcpy(data, content_ptr+length, data_length);
      retval = msghandler_msg_to_payload(msg, data, &msg_ptr);
      if (retval == IOT_SUCCESS) {
        memset(payload, 0, sizeof(payload));
        memcpy(payload, msg_ptr, strlen(msg_ptr));
        
        if (msg_ptr) {
          free(msg_ptr);
          msg_ptr = NULL;
        }
        connections[handle].next_token++;
    
        err = coap_packet_init(&request, connections[handle].coap_buf, sizeof(connections[handle].coap_buf),
                COAP_VERSION, COAP_TYPE_NON_CON,
                sizeof(connections[handle].next_token), (u8_t *)&connections[handle].next_token,
                COAP_METHOD_POST, coap_next_id());
        if (err >= 0) {
          err = coap_packet_append_option(&request, COAP_OPTION_URI_PATH, (u8_t *)NBIOT_RESOURCE, strlen(NBIOT_RESOURCE));
          if (err >= 0) {
            err = coap_packet_append_payload_marker(&request);
            if (err >= 0) {
              err = coap_packet_append_payload(&request, (u8_t *)payload, strlen(payload));
              if (err >= 0) {
                err = send(connections[handle].nbiot_sock, request.data, request.offset, 0);
                if (err >= 0) {
                  printf("CoAP request sent: token 0x%04x\n", connections[handle].next_token);
                  if (frames < i) {
                    loop = 1;
                  }
                  i++;
                }
                else {
                  printf("Failed to send CoAP request, %d\n", errno);
                  retval = IOT_SEND_ERROR;
                }
              }
              else {
                printf("Failed to encode CoAP payload, %d\n", err);
                retval = IOT_COAP_ENCODE_ERROR;
              }
            }
            else {
              printf("Failed to encode CoAP payload marker, %d\n", err);
              retval = IOT_COAP_ENCODE_ERROR;
            }
          }
          else {
            printf("Failed to encode CoAP option, %d\n", err);
            retval = IOT_COAP_ENCODE_ERROR;
          }
        }
        else {
          printf("Failed to create CoAP request, %d\n", err);
          retval = IOT_COAP_REQUEST_ERROR;
        }   
      }
      else {
        printf("msghandler_content_to_payload failed, %d\n", retval);
      }
    } while (loop);

    communication_coap_close(handle);

    if (content_ptr) {
      free(content_ptr);
    }
    
  }
  return retval;
}
