//
//  ARTConfig.h
//  DesktopDirect
//
//  Created by array on 14-3-21.
//  Copyright 2014年 __MyCompanyName__. All rights reserved.
//
#ifndef ArrayDesktopDirect_ARTConfig_h
#define ArrayDesktopDirect_ARTConfig_h
#define MSG_TYPE_GET_INFO 1
#define MSG_TYPE_CLOSING  9999
#define BAKUPPLIST "/usr/local/ArrayDD/bak.plist"
#define INITPLIST "/usr/local/ArrayDD/com.microsoft.rdc.mac.plist"
#define PATH6 "~/Library/Preferences/com.microsoft.rdc.mac.plist"
#define NOPATH6 "~/Library/Containers/com.microsoft.rdc.mac/Data/Library/Preferences/com.microsoft.rdc.mac.plist"

typedef struct {
    int msgType;
} macos_tcs_comm_header;

typedef struct {
    macos_tcs_comm_header hdr;
    //int                   id;
} macos_tcs_comm_get_info;

typedef struct {
    int localPort;
    int height;
    int width;
    int colordepth;
    int redirDrives;
    int redirPrinters;
    int redirPorts;
    int redirSmartCards;
    int redirClipboard;
    int redirPOS;
    int perfFlags;
    int perfWallpaper;
    int perfFullWindowDrag;
    int perfMenuAnim;
    int perfTheme;
    int sound;
    int console;
    int sso;
    char *uname;
    char *pwd;
    char *domain;
    char *startApp;
    char *workDir;
    char *desc;
} macos_tcs_comm_info_reply;

typedef struct info_list
{
    uint iCounter;
    macos_tcs_comm_info_reply rdpInfo[128];
}infoList;



#endif
