#include <zephyr.h>
#include <errno.h>
#include <stdio.h>
#include <modem/at_cmd.h>
#include <modem/at_cmd_parser.h>

#include "device.h"

/*
#define AT_IMEI "AT+CGSN"
#define AT_IMSI "AT+CIMI"

iot_stop_status_t deviceinfo_imei(char* imei, int len) {
  iot_stop_status_t retval = IOT_STOP_SUCCESS;

  int ret;

  ret = at_cmd_write(AT_IMEI, imei, len, NULL);
  if (ret != 0) {
    retval = IOT_STOP_DEVICE_INFO_ERROR;  
  }
  return retval;
}

iot_stop_status_t deviceinfo_imsi(char* imsi, int len) {
  iot_stop_status_t retval = IOT_STOP_SUCCESS;

  int ret;

  ret = at_cmd_write(AT_IMSI, imsi, len, NULL);
  if (ret != 0) {
    retval = IOT_STOP_DEVICE_INFO_ERROR;  
  }
  return retval;
}

iot_stop_status_t deviceinfo_get_info(iot_stop_deviceinfo_command_t deviceinfo, iot_message_t *response) {
  iot_stop_status_t retval = IOT_STOP_SUCCESS;

  char imei[32] = {0};
  char imsi[32] = {0};
  
  switch(deviceinfo) {
	case IOT_STOP_DEVICEINFO_IMEI:
      response->iot_command.iot_deviceinfo = IOT_STOP_DEVICEINFO_IMEI;
        
      retval = deviceinfo_imei((char*)imei, sizeof(imei));
      if (retval == IOT_STOP_SUCCESS) {
        snprintf(response->iot_data, sizeof(response->iot_data), "{\"imei\" : \"%s\"}", imei);
      }
	  break;

	case IOT_STOP_DEVICEINFO_IMSI:
      response->iot_command.iot_deviceinfo = IOT_STOP_DEVICEINFO_IMSI;

      retval = deviceinfo_imsi((char*)imsi, sizeof(imsi));
	  if (retval == IOT_STOP_SUCCESS) {
        snprintf(response->iot_data, sizeof(response->iot_data), "{\"imsi\" : \"%s\"}", imsi);
      }
	  break;

	case IOT_STOP_DEVICEINFO_BATTERY:
	  break;

    case IOT_STOP_DEVICEINFO_FIRMWARE:
	   break;

	case IOT_STOP_DEVICEINFO_ALL:
	   break;

	default: 
	  break; //Response with unknown request?
  }
  
  if (retval != IOT_STOP_SUCCESS) {
    snprintf(response->iot_data, sizeof(response->iot_data), "{\"error\" : \"0x%X\"}", retval); 
  }

  return retval;
}
*/

iot_status_t device(iot_message_s* request, iot_message_s* response) {
  switch(request->content.method) {
    case IOT_METHOD_RESTART:
      break;

    case IOT_METHOD_TURNOFF:
      break;

    case IOT_METHOD_TURNON:
      break;

    default:
      break;
  }
  return IOT_SUCCESS;
}
