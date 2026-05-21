/* A1A1 Readout Tool                                    */
/*                                                      */
/* A command-line tool which scans attached and active  */
/* USB devices for Canon CAPT laser printers, and       */
/* requests device information data throught the CAPT   */
/* 0xA1A1 opcode.                                       */
/* This tool will skip non-Canon, non-CAPT devices to   */
/* avoid bricking unknown devices.                      */
/*                                                      */
/* Public Domain or licensed under CC0                  */
/*                                                      */
/* To the extent possible under law, the author(s) have */
/* dedicated all copyright and related and neighboring  */
/* rights to this software to the public domain         */
/* worldwide. This software is distributed without any  */
/* warranty.                                            */
/*                                                      */
/* You should have received a copy of                   */
/* the CC0 Public Domain Dedication along with this     */
/* software. If not, see:                               */
/* <http://creativecommons.org/publicdomain/zero/1.0/>  */
/*                                                      */

// Written by Moses Chong
// v1.0 released 2026-05-22

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb.h>

#define TABLE(arr) {sizeof(arr)/sizeof(arr[0]), arr} /* prepare table struct */
#define INT_LE_16(x,y) (y << 8 | x)
#define VID_CANON 0x04a9

/* USB ID to Model Number Lookup Table Structures */
struct ID_Model {
    unsigned short int id;
    char *name;
};
struct Table {
    /* wrapper struct to attach size info */
    unsigned short int size;
    struct ID_Model* t;
};
char* lookup(unsigned int id, struct Table table){
    /* lookup function */
    // Table MUST be sorted by id. Adapted from Python bisect_right().
    struct ID_Model* content = table.t;
    unsigned short int max = table.size;
    unsigned short int min = 0;
    unsigned short int i;
    while(max > min){
        i = (max+min)/2;
        if(id < content[i].id){ max = i; }
        else if(id > content[i].id) { min = i+1; }
        else if(content[i].id == id){return content[i].name;}
    }
    return NULL;
}

/* Allowed Product IDs to Model Number Database */
// NOTE: table must be sorted by USB device ID to work
// USB Device IDs from https://usb-ids.gowdy.us/read/UD/04a9
// Please consult the user manual to confirm that your
// Canon laser printer is a CAPT device before adding
// unlisted devices.
// Non-Canon devices without Vendor ID 0x04a9 will be skipped over.
// To protect your equipment, avoid adding non-CAPT devices.
struct ID_Model PRODUCT_IDS[] = {
    {0x260a, "LBP810"},
    {0x2617, "LBP1210"},
    {0x262b, "LBP1120"},
    {0x2636, "LBP3200"},
    {0x2654, "LBP3600"},
    {0x2657, "LBP3210"},
    {0x266a, "LBP3000"},
    {0x266e, "LBP5200"},
    {0x2676, "LBP2900"},
    {0x2679, "LBP5000"},
    {0x267e, "LBP3300"},
    {0x268b, "LBP3500"},
    {0x26a1, "LBP5300"},
    {0x26a4, "LBP5100"},
    {0x26b9, "LBP3310"},
    {0x26ba, "LBP5050"},
    {0x26da, "LBP3010/LBP3018/LBP3050"},
    {0x26db, "LBP3100/LBP3108/LBP3150"},
    {0x26ea, "LBP9100C"},
    {0x26f1, "LBP7200C"},
    {0x26ff, "LBP6300dn"},
    {0x271a, "LBP6000"},
    {0x271b, "LBP6200"},
    {0x271c, "LBP7010C/7018C"},
    {0x2771, "LBP6020"},
};
struct Table PRODUCT_TABLE = TABLE(PRODUCT_IDS);

/* Functions */

void print_hex(unsigned char* s, unsigned int len){
    /* printf hex represenation of every byte from a char* */
    /* NOTE: ending newline *not* included                 */
    for(int i=0; i<len; i++){
        printf("%02x ", s[i]);
    }
    return;
}

char* get_capt_model(libusb_device* dev){
    /* return model number if device is a known CAPT device in */
    /* PRODUCT_TABLE above; or NULL if device is not found     */
    char* m;
    int e=0;
    struct libusb_device_descriptor dd;
    e = libusb_get_device_descriptor(dev, &dd);
    if(e < 0){
        fprintf(stderr, "libusb: Failed to get device descriptor\n");
    }
    if(dd.idVendor != VID_CANON){ return NULL; }
    m = lookup(dd.idProduct, PRODUCT_TABLE);
    if(!m){ return NULL; }
    else { return m; }
}

void print_a1a1(libusb_device* dev){
    struct libusb_config_descriptor* cfg;
    struct libusb_device_handle* dh;
    int e = 0;
    int i = 0; // bulk transfer byte counter
    int iface = 0;
    int s = 0;
    unsigned int timeout = 670;
    unsigned char ep_in = 0x82;  //
    unsigned char ep_out = 0x01; // TODO: not the proper way but I'm lazy
    unsigned char a1a1_req[4] = "\xA1\xA1\x04\x00";
    unsigned char resp_head[6]; // first six bytes of a CAPT response
    unsigned char* resp;
    e = libusb_open(dev, &dh);
    if(e < 0){
        fprintf(stderr, "libusb: Failed to get device handle\n");
        goto end;
    }
    libusb_reset_device(dh);
    // Claim device interface
    e = libusb_get_active_config_descriptor(dev, &cfg);
    if(e < 0){
        fprintf(stderr, "libusb: Failed to get device config\n");
        goto end;
    }
    iface = cfg->interface[0].altsetting[0].bInterfaceNumber;
    libusb_claim_interface(dh, iface);
    // send 0xA1A1 request
    e = libusb_bulk_transfer(
        dh, ep_out, a1a1_req, sizeof(a1a1_req), &i, timeout
    );
    if(e < 0){
        fprintf(stderr, "libusb: Failed to send request\n");
        //fprintf(stderr, "libusb error %d\n", e);
        goto end;
    }
    else if(i < sizeof(a1a1_req)){
        fprintf(stderr, "Could not complete A1A1 request\n");
        goto end;
    }
    // receive 0xA1A1 response (first 6B)
    e = libusb_bulk_transfer(dh, ep_in, resp_head, 6, &i, timeout);
    if(e < 0){
        fprintf(stderr, "libusb: Failed to get response\n");
        goto end;
    }
    else if(i < 6){
        fprintf(stderr, "A1A1 response not complete, got %dB\n",i);
        goto end;
    }
    else if(strncmp(a1a1_req, resp_head, 2)){
        fprintf(stderr, "A1A1 response not detected\n");
        goto end;
    }
    // receive 0xA1A1 response
    s = (INT_LE_16(resp_head[2], resp_head[3]))-sizeof(resp_head);
    resp = malloc(s);
    e = libusb_bulk_transfer(dh, ep_in, resp, s, &i, timeout);
    if(e < 0){
        fprintf(stderr, "libusb: Failed to get response\n");
        goto end;
    }
    if(i < s){
        fprintf(stderr, "A1A1 response not complete, got %dB/%dB\n",i,s);
        goto end;
    }
    // print A1A1 response
    print_hex(resp_head, sizeof(resp_head));
    print_hex(resp, s);
    printf("\n");
    // cleanup
    end:
    if(resp){ free(resp); }
    libusb_release_interface(dh, iface);
    libusb_close(dh);
    return;
}

void print_usage(char* argv0){
    printf("usage: %s [--test [test_usb_id]]\n", argv0);
    printf("--test : Test if a device ID is in the database\n\n");
    printf("When no arguments are given, list A1A1 responses from\n");
    printf("all detected USB Canon CAPT devices.\n\n");
    printf("PROTIP: all diagnostic information is output to stderr\n");
    printf("Try %s 2>/dev/null if scraping output\n", argv0);
    return;
}

int main(int argc, char* argv[]){
    libusb_device **devs;
    libusb_device *dev;
    char* m = "";
    ssize_t what;
    int e;
    unsigned short int i = 0;

    // Options
    if(argc == 2){
        print_usage(argv[0]);
        return 0x1;
    }
    if(argc >= 3){
        // --help option
        if(!strcmp("--help", argv[1])){
            print_usage(argv[0]);
            return 0;
        }
        // --test option
        if(!strcmp("--test", argv[1])){
            unsigned int test_id = strtol(argv[2],NULL,16);
            if((VID_CANON << 16) & test_id){
                unsigned short int d_id = test_id & 0xFFFF;
                char *model = lookup(d_id, PRODUCT_TABLE);
                if(model){
                    printf("TEST: USB ID %08x => %s\n", test_id, model);
                    return 0;
                }
            }
            printf("TEST: device %08x not recognised\n", test_id);
            return 0x02;
        }
    }

    e = libusb_init(NULL);
    if(e < 0){
        fprintf(stderr, "libusb: Could not initialise");
        return e;
    }

    what = libusb_get_device_list(NULL, &devs);
    if(what < 0){
        e = (int) what;
        fprintf(stderr, "libusb: Could not get device list");
        libusb_exit(NULL);
        return e;
    }

    fprintf(stderr, "A1A1 responses from USB CAPT printers\n");
    fprintf(stderr, "=====================================\n");
    dev = devs[i];
    while(dev){
        m = get_capt_model(dev);
        if(m){
            printf("%s: ", m);
            print_a1a1(dev);
        }
        else{
            //fprintf(stderr, "Skipping non-CAPT device\n");
        }
        dev = devs[++i];
    }

    libusb_free_device_list(devs, 1);
    libusb_exit(NULL);
    return 0;
}

