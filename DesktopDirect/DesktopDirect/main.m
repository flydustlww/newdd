//
//  main.m
//  DesktopDirect
//
//  Created by array on 14-3-21.
//  Copyright 2014年 __MyCompanyName__. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include "ARTConfig.h"
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFArray.h>
#include <Security/Security.h>
#include <Security/SecKeychainItem.h>
#include <Security/SecAccess.h>
#include <CoreServices/CoreServices.h>

SecKeychainItemRef keyChainItemList[128];
int keyItemCount =0;
SecAccessRef createAccess(NSString *accessLabel)
{
	OSStatus err;
    
	SecAccessRef access=nil;
	NSArray *trustedApplications=nil;
    
	//Make an exception list of trusted applications; that is,
	// applications that are allowed to access the item without
	// requiring user confirmation:
	SecTrustedApplicationRef myself, someOther;
    
	//Create trusted application references; see SecTrustedApplications.h:
	err = SecTrustedApplicationCreateFromPath(NULL, &myself);
	err = err ?: SecTrustedApplicationCreateFromPath("/Applications/Microsoft Remote Desktop.app", &someOther);
    
	if (err == noErr) {
		//trustedApplications = [NSArray arrayWithObjects:(__bridge_transfer id)myself,
		//  (__bridge_transfer id)someOther, nil];
		//trustedApplications = [NSArray arrayWithObjects:(__bridge id)myself, (__bridge id)someOther, nil];
        trustedApplications = [NSArray arrayWithObjects:(id)myself, (id)someOther, nil];
	}
    
	//Create an access object:
	//err = err ?: SecAccessCreate((__bridge CFStringRef)accessLabel,
	//(__bridge CFArrayRef)trustedApplications, &access);
	//err = err ?: SecAccessCreate((__bridge CFStringRef)accessLabel, (__bridge CFArrayRef)trustedApplications, &access);
    err = err ?: SecAccessCreate((CFStringRef)accessLabel, (CFArrayRef)trustedApplications, &access);
    if (err) return nil;
    
	return access;
}

OSStatus addInternetPassword(NSString *password, NSString *account,
                             NSString *server, NSString *itemLabel, NSString *path,
                             SecProtocolType protocol, int port, SecKeychainItemRef *item)
{
	OSStatus err;
	//SecKeychainItemRef item = nil;
    
	const char *pathUTF8 = [path UTF8String];
	const char *serverUTF8 = [server UTF8String];
	const char *accountUTF8 = [account UTF8String];
	const char *passwordUTF8 = [password UTF8String];
	const char *itemLabelUTF8 = [itemLabel UTF8String];
    
	//Create initial access control settings for the item:
	SecAccessRef access = createAccess(itemLabel);
    
	//Following is the lower-level equivalent to the
	// SecKeychainAddInternetPassword function:
    
	//Set up the attribute vector (each attribute consists
	// of {tag, length, pointer}):
    
	SecKeychainAttribute attrs[] = {
		{ kSecLabelItemAttr, (UInt32)strlen(itemLabelUTF8), (char *)itemLabelUTF8 },
		{ kSecAccountItemAttr, (UInt32)strlen(accountUTF8), (char *)accountUTF8 },
		{ kSecServerItemAttr, (UInt32)strlen(serverUTF8), (char *)serverUTF8 },
		{ kSecPortItemAttr, sizeof(int), (int *)&port },
		{ kSecProtocolItemAttr, sizeof(SecProtocolType),
			(SecProtocolType *)&protocol },
		{ kSecPathItemAttr, (UInt32)strlen(pathUTF8), (char *)pathUTF8 }
	};
	SecKeychainAttributeList attributes = { sizeof(attrs) / sizeof(attrs[0]), attrs };
    
	err = SecKeychainItemCreateFromContent(
                                           kSecInternetPasswordItemClass,
                                           &attributes,
                                           (UInt32)strlen(passwordUTF8),
                                           passwordUTF8,
                                           NULL, // use the default keychain
                                           access,
                                           item);
    
	if (access) CFRelease(access);
	//	if (item) CFRelease(item);
    
	return err;
}

int forknexec(char *cmd, int delay)
{
	pid_t pid;
	int stat;
    
	if(cmd == NULL)
	{
		return 1;
	}
	if ((pid = fork()) >0){
		waitpid(pid, &stat, 0);
		if(delay){
			sleep(delay);
		}
	} else if (pid <0){
		stat = -1;
	} else {
		setuid(0);
		seteuid(0);
		execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);
		syslog(LOG_ERR, "function: %s:Execute %s failed!", __func__, cmd);
		exit(1);
	}
	return stat;
}

int launchMicroRDC(char *label)
{
	int ret;
	char cmd[1024]={0};
    
	syslog(LOG_ERR, "function: %s:enter launch,label is %s\n", __func__, label);
	sprintf(cmd, "/usr/bin/osascript ~/Library/Containers/com.microsoft.rdc.mac/Data/Library/Preferences/start.applescript %s", label);
	ret = forknexec(cmd, 0);
	syslog(LOG_ERR, "function: %s:Execute launch applescript ret is %d", __func__, ret);
	return 0;
}

void bufReadInt(char *prmBuf, int *prmIndex, int *prmInt) {
	*prmInt = htonl(*((int *)&prmBuf[(*prmIndex)]));
	*prmIndex += sizeof(int);
}

char *bufReadString(char *prmBuf, int *prmIndex){
	char *buf = NULL;
	int len = htonl(*((int *)&prmBuf[(*prmIndex)]));
	*prmIndex += sizeof(int);
    
    
	if (len > 0) {
		buf = (char *)malloc(len+1);
		buf[len] = 0;
		memcpy(buf, &prmBuf[(*prmIndex)], len);
		*prmIndex += len;
	}
    
	return buf;
}

OSStatus addPasswdToKeychain(char *userName, int port, char *label, NSString *uuid, char *passwd, SecKeychainItemRef *item, char *domain){
    
	//Add an password to the keychain:
	OSStatus status;
    NSString *account = [[[NSString alloc] init] autorelease];
    
	NSString *pwd = [NSString stringWithCString:passwd encoding:NSUTF8StringEncoding];
    if(domain == NULL) {
        account = [NSString stringWithCString:userName encoding:NSUTF8StringEncoding];
    } else {
        NSString *ddomain =[NSString stringWithCString:domain encoding:NSUTF8StringEncoding];
        NSString *uname = [NSString stringWithCString:userName encoding:NSUTF8StringEncoding];
        account = [NSString stringWithFormat:@"%@\\%@",ddomain,uname];
    }
	NSString *itemLabel = [NSString stringWithCString:label encoding:NSUTF8StringEncoding];
    NSLog(@"enter addPasswdToKeychain UUID is %@, label is %@", uuid, itemLabel);
	status = addInternetPassword(pwd, account, @"127.0.0.1", itemLabel, uuid, kSecProtocolTypeAny, port, item);
	return status;
}

bool checkBookmarkExists(char *desc, NSString *path) {
	NSUInteger index;
    
    syslog(LOG_ERR, "Enter checkBookmarkExists!");
	NSString *label =[NSString stringWithFormat:@"AN_%s",desc];
	NSMutableDictionary *plist = [[NSMutableDictionary alloc] initWithContentsOfFile:path];
	NSMutableArray *newArray;
	newArray = [plist objectForKey:@"bookmarkorder.ids"];
	for (index=0; index< [newArray count]; index++) {
		NSLog(@"the %lu id is %@", (unsigned long)index, [newArray objectAtIndex:index]);
		NSString *key = [NSString stringWithFormat:@"bookmarks.bookmark.%@.label", [newArray objectAtIndex:index]];
		NSString *valueOfKey = [plist objectForKey:key];
		NSLog(@"value is %@", valueOfKey);
		if([valueOfKey isEqualToString:label])
		{
			NSLog(@"this label exists! no need to add bookmark again!");
			return true;
		}
	}
    [plist release];
	return false;
}

int exitDDRestorePlist(int sso, SecKeychainItemRef *itemRef) {
	char cmd[1024]={0};
	OSStatus status = 0;
    
	syslog(LOG_ERR, "function: %s:Enter exitDDRestorePlist!", __func__);
	//forknexec((char *)RESTOREPLIST, 0);
	//update plist cache
	syslog(LOG_ERR, "function: %s:finish remove keys, update Cache of Plist!", __func__);
	sprintf(cmd, "killall -u $USER cfprefsd");
	int ret = forknexec(cmd, 0);
    
	//delete password from keychain
	if(sso == 1){
		status =SecKeychainItemDelete(*itemRef);
	}
    
	syslog(LOG_ERR, "function: %s:after remove bookmark, Execute update plist cache ret is %d", __func__, ret);
	return status;
}

OSStatus initRemoveArrayBookmarks(NSString *path, bool isMacOS6){
	NSUInteger index;
	NSString *existkey;
	NSString *valueOfKey;
	NSString *key;
	NSString *tmpkey;
	int ret;
	char cmd[1024] = {0};
    NSMutableArray *newArray =[[[NSMutableArray alloc] init] autorelease];
    
    syslog(LOG_ERR, "Enter initRemoveArrayBookmarks!");
    sprintf(cmd, "killall \"Microsoft Remote Desktop\"");
    ret = forknexec(cmd, 0);
	NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    newArray = [plist objectForKey:@"bookmarkorder.ids"];
    NSUInteger count = [newArray count];
    if(count == 0){
        syslog(LOG_ERR, "no bookmarkorder.ids, count is 0!");
        return 0;
    }
    NSMutableArray *anBookmarks=[[[NSMutableArray alloc] init] autorelease];
    for (index=0; index< count; index++) {
        //NSLog(@"index is %lu,count is %lu",(unsigned long)index,(unsigned long)count);
        existkey = [NSString stringWithFormat:@"bookmarks.bookmark.%@.label", [newArray objectAtIndex:index]];
        valueOfKey = [plist objectForKey:existkey];
        if([valueOfKey hasPrefix:@"AN_"])
        {
            NSLog(@"this label %@ is added by array DD Client!should be remove",valueOfKey);
            [anBookmarks addObject:[NSString stringWithFormat:@"bookmarks.bookmark.%@",[newArray objectAtIndex:index]]];
            [newArray removeObjectAtIndex:index];
            index--;
            count--;
        }
    }
    if(newArray !=NULL) {
        [plist setObject:newArray forKey:@"bookmarkorder.ids"];
    }
    syslog(LOG_ERR, "finish delete uuids for each bookmark!");
    for (NSUInteger i=0; i < [anBookmarks count]; i++) {
        tmpkey = [anBookmarks objectAtIndex:i];
        key = [NSString stringWithFormat:@"%@.label",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.hostname",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.username",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.printerForwarding",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.authenticationLevel",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.remoteProgram",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.sound",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.depth",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.resolution",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.windowsThemes",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.menuAnimation",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.drawWallpaper",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.windowDrag",tmpkey];
        [plist removeObjectForKey:key];
        key = [NSString stringWithFormat:@"%@.consoleSession",tmpkey];
        [plist removeObjectForKey:key];
    }
    syslog(LOG_ERR, "finish delete keys added for each bookmark!");
    [plist writeToFile:path atomically:YES];
	//update plish cache
    if(!isMacOS6){
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "killall -u $USER cfprefsd");
        ret = forknexec(cmd, 0);
    }
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "defaults read com.microsoft.rdc.mac");
    ret = forknexec(cmd, 0);
    syslog(LOG_ERR, "after initremove array bookmarks, update plist cache!");
	return 0;
}

OSStatus removeArrayBookmarks(NSString *path, bool isMacOS6){
	int ret;
	char cmd[1024] = {0};
    
    syslog(LOG_ERR, "Enter RemoveArrayBookmarks!");
    sprintf(cmd, "killall \"Microsoft Remote Desktop\"");
    ret = forknexec(cmd, 0);
    
	//update plish cache
    memset(cmd, 0, sizeof(cmd));
    if (isMacOS6) {
        sprintf(cmd, "/bin/cp -f %s %s", BAKUPPLIST, PATH6);
    } else {
        sprintf(cmd, "/bin/cp -f %s %s", BAKUPPLIST, NOPATH6);
    }
    ret = forknexec(cmd, 0);
    //update plist cache
    if(!isMacOS6){
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "killall -u $USER cfprefsd");
        ret = forknexec(cmd, 0);
    }
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "defaults read com.microsoft.rdc.mac");
    ret = forknexec(cmd, 0);
    
    syslog(LOG_ERR, "after remove array bookmarks, update plist cache!");
	return 0;
}

NSString * addBookmarkToPlist(macos_tcs_comm_info_reply info[], int infoNum, NSString *path, bool isMacOS6)
{
	SecKeychainItemRef keyChainItem;
	int ret,i;
    char cmd[1024]={0};
	NSString *key;
	NSMutableArray *newArray =[[[NSMutableArray alloc] init] autorelease];
	NSString      *uuid;
	uuid_t      csuuid;
	char str_uuid[1024] = {0};
    
    syslog(LOG_ERR, "Enter addBookmakrToPlist!");
	NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    [plist removeAllObjects];
    [plist writeToFile:path atomically:YES];
    
    for (i=0; i < infoNum; i++) {
		//if(!checkBookmarkExists(info[i].desc, path)) {
        syslog(LOG_ERR,"add %d bookmark %s", i, info[i].desc);
        uuid_generate(csuuid);
        uuid_unparse_lower(csuuid, str_uuid);
        uuid = [NSString stringWithFormat:@"{%s}", str_uuid];
        key = [NSString stringWithFormat:@"bookmarks.bookmark.%@", uuid];
        if(info[i].desc!=NULL) {
            NSString *label = [NSString stringWithFormat:@"AN_%s",info[i].desc];
            [plist setObject:label forKey:[key stringByAppendingString:@".label"]];
        } else {
            syslog(LOG_ERR, "info.desc is null!");
        }
        if((info[i].perfFlags & 0x8) == 0){
            NSNumber *themes = [NSNumber numberWithBool:NO];
            [plist setObject:themes forKey:[key stringByAppendingString:@".windowsThemes"]];
        }
        if((info[i].perfFlags & 0x4) == 0){
            NSNumber *menuAnim = [NSNumber numberWithBool:NO];
            [plist setObject:menuAnim forKey:[key stringByAppendingString:@".menuAnimation"]];
        }
        if((info[i].perfFlags & 0x1) == 0){
            NSNumber *wallPaper = [NSNumber numberWithBool:NO];
            [plist setObject:wallPaper forKey:[key stringByAppendingString:@".drawWallpaper"]];
        }
        if((info[i].perfFlags & 0x2) == 0){
            NSNumber *windowDrag = [NSNumber numberWithBool:NO];
            [plist setObject:windowDrag forKey:[key stringByAppendingString:@".windowDrag"]];
        }
        
        NSString *hostName = [NSString stringWithFormat:@"127.0.0.1:%d", info[i].localPort];
        [plist setObject:hostName forKey:[key stringByAppendingString:@".hostname"]];
        if(info[i].colordepth > 0) {
            NSNumber *colorDepth = [NSNumber numberWithInt:info[i].colordepth];
            [plist setObject:colorDepth forKey:[key stringByAppendingString:@".depth"]];
        }
        if(info[i].startApp!=NULL){
            //NSString *app = [NSString stringWithFormat:@"%s", info[i].startApp];
            NSString *app = [NSString stringWithCString:info[i].startApp encoding:NSASCIIStringEncoding];
            [plist setObject:app forKey:[key stringByAppendingString:@".remoteProgram"]];
        }
        if (info[i].height>0 && info[i].width>0) {
            NSString *resolution = [NSString stringWithFormat:@"@Size(%d %d)",info[i].height,info[i].width];
            [plist setObject:resolution forKey:[key stringByAppendingString:@".resolution"]];
        }
        if(info[i].sound ==1){
            NSString *sound = [NSString stringWithFormat:@"@Variant(HLW::SoundMode)"];
            [plist setObject:sound forKey:[key stringByAppendingString:@".sound"]];
        }
        if(info[i].console ==1){
            NSNumber *consoleSession = [NSNumber numberWithBool:YES];
            [plist setObject:consoleSession forKey:[key stringByAppendingString:@".consoleSession"]];
        }
        if(info[i].redirPrinters ==1){
            NSNumber *redirPrint = [NSNumber numberWithBool:YES];
            [plist setObject:redirPrint forKey:[key stringByAppendingString:@".printerForwarding"]];
        }
        if(info[i].sso == 1) {
            if((info[i].uname != NULL) && (info[i].domain ==NULL)) {
                NSString *account = [NSString stringWithCString:info[i].uname encoding:NSUTF8StringEncoding];
                [plist setObject:account forKey:[key stringByAppendingString:@".username"]];
            }
            if((info[i].uname != NULL) && (info[i].domain !=NULL)) {
                NSString *account = [NSString stringWithFormat:@"%s\\%s", info[i].domain,info[i].uname];
                [plist setObject:account forKey:[key stringByAppendingString:@".username"]];
            }
            //for SSO add passwd into keychain
            if(info[i].pwd != NULL && info[i].desc!=NULL && info[i].uname!=NULL) {
                ret = addPasswdToKeychain(info[i].uname, info[i].localPort, info[i].desc, uuid, info[i].pwd, &keyChainItem, info[i].domain);
                keyChainItemList[keyItemCount]=keyChainItem;
                if(ret != 0){
                    syslog(LOG_ERR,"function: %s:add password to keychain failed!", __func__);
                }
                keyItemCount++;
            }
        }
        NSNumber *authLevel = [NSNumber numberWithInt:0];
        [plist setObject:authLevel forKey:[key stringByAppendingString:@".authenticationLevel"]];
        if(i >0) {
            newArray = [plist objectForKey:@"bookmarkorder.ids"];
        }
        [newArray addObject:uuid];
        [plist setObject:newArray forKey:@"bookmarkorder.ids"];
        
		//}
	}
    do {
        uuid_generate(csuuid);
        uuid_unparse_lower(csuuid, str_uuid);
        uuid = [NSString stringWithFormat:@"{%s}", str_uuid];
        key = [NSString stringWithFormat:@"bookmarks.bookmark.%@", uuid];
        if(info[infoNum-1].desc!=NULL) {
            NSString *label = [NSString stringWithFormat:@"AN_%s_as",info[infoNum-1].desc];
            [plist setObject:label forKey:[key stringByAppendingString:@".label"]];
        } else {
            syslog(LOG_ERR, "info.desc is null!");
        }
        if((info[infoNum-1].perfFlags & 0x8) == 0){
            NSNumber *themes = [NSNumber numberWithBool:NO];
            [plist setObject:themes forKey:[key stringByAppendingString:@".windowsThemes"]];
        }
        if((info[infoNum-1].perfFlags & 0x4) == 0){
            NSNumber *menuAnim = [NSNumber numberWithBool:NO];
            [plist setObject:menuAnim forKey:[key stringByAppendingString:@".menuAnimation"]];
        }
        if((info[infoNum-1].perfFlags & 0x1) == 0){
            NSNumber *wallPaper = [NSNumber numberWithBool:NO];
            [plist setObject:wallPaper forKey:[key stringByAppendingString:@".drawWallpaper"]];
        }
        if((info[infoNum-1].perfFlags & 0x2) == 0){
            NSNumber *windowDrag = [NSNumber numberWithBool:NO];
            [plist setObject:windowDrag forKey:[key stringByAppendingString:@".windowDrag"]];
        }
        
        NSString *hostName = [NSString stringWithFormat:@"127.0.0.1:%d", info[infoNum-1].localPort];
        [plist setObject:hostName forKey:[key stringByAppendingString:@".hostname"]];
        if(info[infoNum-1].colordepth > 0) {
            NSNumber *colorDepth = [NSNumber numberWithInt:info[infoNum-1].colordepth];
            [plist setObject:colorDepth forKey:[key stringByAppendingString:@".depth"]];
        }
        if(info[infoNum-1].startApp!=NULL){
            NSString *app = [NSString stringWithCString:info[infoNum-1].startApp encoding:NSASCIIStringEncoding];
            [plist setObject:app forKey:[key stringByAppendingString:@".remoteProgram"]];
        }
        if (info[infoNum-1].height>0 && info[infoNum-1].width>0) {
            NSString *resolution = [NSString stringWithFormat:@"@Size(%d %d)",info[infoNum-1].height,info[infoNum-1].width];
            [plist setObject:resolution forKey:[key stringByAppendingString:@".resolution"]];
        }
        if(info[infoNum-1].sound ==1){
            NSString *sound = [NSString stringWithFormat:@"@Variant(HLW::SoundMode)"];
            [plist setObject:sound forKey:[key stringByAppendingString:@".sound"]];
        }
        if(info[infoNum-1].console ==1){
            NSNumber *consoleSession = [NSNumber numberWithBool:YES];
            [plist setObject:consoleSession forKey:[key stringByAppendingString:@".consoleSession"]];
        }
        if(info[infoNum-1].redirPrinters ==1){
            NSNumber *redirPrint = [NSNumber numberWithBool:YES];
            [plist setObject:redirPrint forKey:[key stringByAppendingString:@".printerForwarding"]];
        }
        NSNumber *authLevel = [NSNumber numberWithInt:0];
        [plist setObject:authLevel forKey:[key stringByAppendingString:@".authenticationLevel"]];
            newArray = [plist objectForKey:@"bookmarkorder.ids"];
        [newArray addObject:uuid];
        [plist setObject:newArray forKey:@"bookmarkorder.ids"];
        
    } while(0);
    NSNumber *showDialog = [NSNumber numberWithBool:NO];
    [plist setObject:showDialog forKey:@"show_whats_new_dialog"];
	[plist writeToFile:path atomically:YES];
    
    //update plish cache
    if(!isMacOS6){
        memset(cmd, 0, sizeof(cmd));
        sprintf(cmd, "killall -u $USER cfprefsd");
        ret = forknexec(cmd, 0);
    }
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "defaults read com.microsoft.rdc.mac");
    ret = forknexec(cmd, 0);
    
    syslog(LOG_ERR, "finish addbookmarks and update plist cache!");
    return NULL;
}

int recvARTConfigInfo(struct sockaddr_in dest_addr, int *sock, macos_tcs_comm_info_reply *info, macos_tcs_comm_get_info getInfo, int count)
{
	char buf[4*1024];
	int i, t;
	int ctl_sock;
	struct fd_set sset;
	struct timeval to;
	size_t len;
    
	syslog(LOG_ERR, "function: %s:Enter recvARTConfigInfo!", __func__);
	ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctl_sock < 0) {
		syslog(LOG_ERR, "function: %s:create socket failed, err info %s", __func__, strerror(errno));
		return -1;
	}
	sleep(2);
	len = sendto(ctl_sock, &getInfo, sizeof(getInfo), 0, (struct sockaddr *)&dest_addr,sizeof(dest_addr));
	syslog(LOG_ERR, "sent to java %zu bytes",len);
	// Mark socket as non-blocking
	t = 1;
	i = ioctl(ctl_sock, FIONBIO, (char *)&t);
	if (i < 0) {
		close(ctl_sock);
		return -1;
	}
    
	// Prepare for select
	FD_ZERO(&sset);
	FD_SET(ctl_sock, &sset);
	t = ctl_sock;
	// Set the timeout to 30 seconds, if we don't hear back from the TCS after 30 seconds the launch has failed
	to.tv_sec = 30;
	to.tv_usec = 0;
    
	select(t+1, &sset, NULL, NULL, &to);
	len = recv(ctl_sock, &buf, sizeof(buf), 0);
	if (len <= 0) {
		close(ctl_sock);
		return -1;
	}
	syslog(LOG_ERR, "function: %s:hosts num is %d",__func__, count);
	//for(int m=0;m<count;m++){
	memset(info, 0, sizeof(*info));
    
	i = 0;
	bufReadInt(buf, &i, &info->localPort);
	bufReadInt(buf, &i, &info->height);
	bufReadInt(buf, &i, &info->width);
	bufReadInt(buf, &i, &info->colordepth);
	bufReadInt(buf, &i, &info->redirDrives);
	bufReadInt(buf, &i, &info->redirPrinters);
	bufReadInt(buf, &i, &info->redirPorts);
	bufReadInt(buf, &i, &info->redirSmartCards);
	bufReadInt(buf, &i, &info->redirClipboard);
	bufReadInt(buf, &i, &info->redirPOS);
	bufReadInt(buf, &i, &info->perfFlags);
	bufReadInt(buf, &i, &info->sound);
	bufReadInt(buf, &i, &info->console);
	bufReadInt(buf, &i, &info->sso);
	syslog(LOG_ERR, "function: %s:sso is %d,listen port is %d",__func__, info->sso, info->localPort);
	if (info->sso == 1) {
		info->uname = bufReadString(buf, &i);
		info->pwd = bufReadString(buf, &i);
	} else {
		info->uname = NULL;
		info->pwd = NULL;
	}
	syslog(LOG_ERR, "function: %s:desc is %s,uname is %s",__func__,info->desc,info->uname);
	info->domain = bufReadString(buf, &i);
	info->startApp = bufReadString(buf, &i);
	info->workDir = bufReadString(buf, &i);
	info->desc = bufReadString(buf, &i);
	//}
	*sock =ctl_sock;
    
	return 0;
}

int getMicroRDCPid(void)
{
	char buf_ps[1024]={0};
	char ps[1024]={0};
	FILE *ptr;
    
	syslog(LOG_ERR, "function: %s:Enter getMicroRDC Pid!", __func__);
	strcpy(ps, "ps ax|grep \"Microsoft Remote Desktop\"|grep -v \"grep\"|awk '{printf $1}'");
	if((ptr=popen(ps, "r"))!=NULL)
	{
		while(fgets(buf_ps, 1024, ptr)!=NULL)
		{
			syslog(LOG_ERR, "function: %s:Microsoft Remote Desktop PID is %s", __func__, buf_ps);
			return atoi(buf_ps);
		}
		pclose(ptr);
		ptr = NULL;
		return -2;
	}
	else
	{
		syslog(LOG_ERR, "function: %s:popen %s error\n", __func__, ps);
	}
	return -1;
}

void *detectMicroRDCThreadFun(void *prmArg)
{
	return NULL;
}

int updateVDIResConf(NSString *desc, int port){
    int ret;
    char cmd[1024]={0};
    NSUInteger index;
    NSLog(@"enter updateVDIResConf desc is %@, port is %d", desc, port);
    NSString *label =[NSString stringWithFormat:@"AN_%@",desc];
    NSString *path;
    NSDictionary *systemVersionDictionary = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *systemVersion = [systemVersionDictionary objectForKey:@"ProductVersion"];
    if([systemVersion hasPrefix:@"10.6"]){ 
        path =[[NSString alloc] initWithFormat:@"%s/Library/Preferences/com.microsoft.rdc.mac.plist",getenv("HOME")];
    } else {
        path =[[NSString alloc] initWithFormat:@"%s/Library/Containers/com.microsoft.rdc.mac/Data/Library/Preferences/com.microsoft.rdc.mac.plist",getenv("HOME")];
    }
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    NSMutableArray *newArray;
    NSString *vdiKey = [[NSString alloc] init];
	newArray = [plist objectForKey:@"bookmarkorder.ids"];
	for (index=0; index< [newArray count]; index++) {
		NSString *key = [NSString stringWithFormat:@"bookmarks.bookmark.%@.label", [newArray objectAtIndex:index]];
		NSString *valueOfKey = [plist objectForKey:key];
		if([valueOfKey isEqualToString:label])
		{
            NSLog(@"value is %@", valueOfKey);
            vdiKey = [NSString stringWithFormat:@"bookmarks.bookmark.%@",[newArray objectAtIndex:index]];
			break;
		}
	}
    NSString *hostName = [NSString stringWithFormat:@"127.0.0.1:%d", port];
    [plist setObject:hostName forKey:[vdiKey stringByAppendingString:@".hostname"]];
    [plist writeToFile:path atomically:YES];
    //update plish cache
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "defaults read com.microsoft.rdc.mac");
    ret = forknexec(cmd, 0);
    [path release];
    [vdiKey release];
    return ret;
}

void moniterAppletExit(int *sock, NSString *path, bool isMacOS6)
{
    struct sockaddr_in serv_addr;
    //long t;
    int ctl_sock;
    size_t len;
    int flag =1;
    socklen_t so_len;
    char buf[256];
    OSStatus status;
    //NSString *tempDesc;
    
    syslog(LOG_ERR, "Enter moniterAppletExit!");
    ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ctl_sock ==-1){
        NSLog(@"create ctl_sock fail");
        return ;
    }
    so_len = sizeof(int);
    if (setsockopt(ctl_sock, SOL_SOCKET, SO_REUSEADDR, &flag, so_len) !=0) {
        NSLog(@"set sock reuse option failed");
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(6666);
    if(bind(ctl_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))== -1){
        syslog(LOG_ERR, "monitor bind sock failed, errno is %d, info is %s", errno, strerror(errno));
        return ;
    }
    NSLog(@"java socket listen begin recv");
    do {
        memset(buf, 0, sizeof(buf));
        NSLog(@"begin to recv on local socket");
        len = recv(ctl_sock, &buf, sizeof(buf), 0);
        NSLog(@"receive buf is %s,len is %lu",buf,len);
        
        //        if (strstr(buf, "###")!=NULL) {
        //            t=strstr(buf, "###")-buf;
        //            tempDesc = [NSString stringWithFormat:@"%s", buf];
        //            NSString *desc = [tempDesc substringToIndex:t];
        //            updateVDIResConf(desc, atoi(strstr(buf, "###")+3));
        //        }
        if(strncmp(buf, "ExitDD",6)==0){
            NSLog(@"Exit DD Client!");
            removeArrayBookmarks(path, isMacOS6);
            for(int m=0; m<keyItemCount; m++){
                status =SecKeychainItemDelete(keyChainItemList[m]);
            }
            close(ctl_sock);
            return;
        }
    } while(0);
}

int startCtlSocket(int *sockctl)
{
	int n=0;
	int sock = -1;
	int tmpsock =-1;
	struct sockaddr_in serveraddr;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	NSLog(@"enter startCtlSocket");
	if(sock == -1){
		NSLog(@"Create sock error");
		exit(0);
	}
	memset(&serveraddr,0,sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	inet_aton("127.0.0.1", &serveraddr.sin_addr);
	serveraddr.sin_port = htons(6666);
    
	n = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &n, sizeof(n)) < 0) {
		NSLog(@"Create set sock opt error");
	}
    
    
	n = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n)) < 0) {
		NSLog(@"Create set sock opt error");
	}
    
	struct linger m_sLinger;
	m_sLinger.l_onoff = 1;
	m_sLinger.l_linger = 0;
	setsockopt(sock,SOL_SOCKET,SO_LINGER,(void *)&m_sLinger,sizeof(struct linger));
	if(bind(sock,(struct sockaddr*)&serveraddr, sizeof(serveraddr)) == -1){
		NSLog(@"Create bind sock opt error");
		exit(0);
	}
	if(listen(sock,100)==-1){
		NSLog(@"Create listen sock opt error");
		exit(0);
	}
	NSLog(@"begin accept ctl sock is %d",sock);
	if((tmpsock = accept(sock, (struct sockaddr*)NULL,NULL))==-1){
		NSLog(@"Create listen sock opt error");
	}
	NSLog(@"accept socke is %d",tmpsock);
	*sockctl =tmpsock;
	return 0;
}

int main (int argc, const char * argv[])
{
    
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
    
    // insert code here...
    int ret;
    bool MacOS6 = false;
    //int sock = -1;
    //pid_t pid;
    //infoList* confList=NULL;
    NSString *key;
    //		int count =0;
    macos_tcs_comm_get_info getInfo;
    macos_tcs_comm_info_reply confList[256];
    struct sockaddr_in dest_addr;
    char buf[4*1024];
    int i,t,configNum,deleNum;
    int ctl_sock;
    struct fd_set sset;
    struct timeval to;
    int len;
    char cmd[1024]={0};
    
    
    if (argc < 3) {
        syslog(LOG_ERR, "java start DD error");
        return -1;
    }
    NSString *path;
    NSDictionary *systemVersionDictionary = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSString *systemVersion = [systemVersionDictionary objectForKey:@"ProductVersion"];
    if([systemVersion hasPrefix:@"10.6"]){ 
        path =[[NSString alloc] initWithFormat:@"%s/Library/Preferences/com.microsoft.rdc.mac.plist",getenv("HOME")];
        [path autorelease];
        MacOS6 = true;
    } else {
        path =[[NSString alloc] initWithFormat:@"%s/Library/Containers/com.microsoft.rdc.mac/Data/Library/Preferences/com.microsoft.rdc.mac.plist",getenv("HOME")]; 
        [path autorelease];
    }
    initRemoveArrayBookmarks(path, MacOS6);
    //backup plist file
    if (MacOS6) {
        sprintf(cmd, "/bin/cp -f %s %s", PATH6, BAKUPPLIST);
        ret = forknexec(cmd, 0);
    } else {
        sprintf(cmd, "/bin/cp -f %s %s", NOPATH6, BAKUPPLIST);
        ret = forknexec(cmd, 0);
    }
    ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl_sock < 0) {
        syslog(LOG_ERR, "function: %s:create ctl_sock failed, err info %s", __func__, strerror(errno));
        return -1;
    }
    NSLog(@"CTL sock is %d",ctl_sock);
    memset(&dest_addr, 0, sizeof(dest_addr));
    
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest_addr.sin_port = htons(atoi(argv[1]));
    syslog(LOG_ERR, "Port is %d,desktop num is %d",atoi(argv[1]),atoi(argv[2]));
    getInfo.hdr.msgType = htonl(MSG_TYPE_GET_INFO);
    //getInfo.id = htonl(atoi(argv[2]));
    len = sendto(ctl_sock, &getInfo, sizeof(getInfo), 0, (struct sockaddr *)&dest_addr,sizeof(dest_addr));
    syslog(LOG_ERR, "sent to java %zu bytes",len);
    // Mark socket as non-blocking
    t = 1;
    ret = ioctl(ctl_sock, FIONBIO, (char *)&t);
    if (ret < 0) {
        syslog(LOG_ERR, "mark socket as non-blocking failed ioctl");
    }
    int count = atoi(argv[2]);
    // Prepare for select
    for (configNum =0; configNum < count; configNum++) {
        memset(buf, 0, sizeof(buf));    
        FD_ZERO(&sset);
        FD_SET(ctl_sock, &sset);
        t = ctl_sock;
        // Set the timeout to 30 seconds
        to.tv_sec = 30;
        to.tv_usec = 0;
        
        select(t+1, &sset, NULL, NULL, NULL);
        len = recv(ctl_sock, &buf, sizeof(buf), 0);
        syslog(LOG_ERR,"recv return len :%d, the %d desktop",len, configNum);
        
        if (len <= 0) {
            close(ctl_sock);
            break;
        }
        i = 0;
        
        //for(m=0; m < count; m++){
        memset(&confList[configNum], 0, sizeof(confList[configNum]));
        
        bufReadInt(buf, &i, &confList[configNum].localPort);
        bufReadInt(buf, &i, &confList[configNum].height);
        bufReadInt(buf, &i, &confList[configNum].width);
        bufReadInt(buf, &i, &confList[configNum].colordepth);
        bufReadInt(buf, &i, &confList[configNum].redirDrives);
        bufReadInt(buf, &i, &confList[configNum].redirPrinters);
        bufReadInt(buf, &i, &confList[configNum].redirPorts);
        bufReadInt(buf, &i, &confList[configNum].redirSmartCards);
        bufReadInt(buf, &i, &confList[configNum].redirClipboard);
        bufReadInt(buf, &i, &confList[configNum].redirPOS);
        bufReadInt(buf, &i, &confList[configNum].perfFlags);
        bufReadInt(buf, &i, &confList[configNum].sound);
        bufReadInt(buf, &i, &confList[configNum].console);
        bufReadInt(buf, &i, &confList[configNum].sso);
        //syslog(LOG_ERR, "function: %s:sso is %d,listen port is %d",__func__, confList[m].sso, confList[m].localPort);
        if (confList[configNum].sso == 1) {
            confList[configNum].uname = bufReadString(buf, &i);
            confList[configNum].pwd = bufReadString(buf, &i);
        } else {
            confList[configNum].uname = NULL;
            confList[configNum].pwd = NULL;
        }
        confList[configNum].domain = bufReadString(buf, &i);
        confList[configNum].startApp = bufReadString(buf, &i);
        confList[configNum].workDir = bufReadString(buf, &i);
        confList[configNum].desc = bufReadString(buf, &i);
    }
    
    syslog(LOG_ERR, "finish receive ART config informations!");
    key = addBookmarkToPlist(confList, configNum, path, MacOS6);
    
    moniterAppletExit(&ctl_sock, path, MacOS6);
    for(deleNum =0; deleNum <configNum; deleNum++){
        if (confList[deleNum].uname != NULL) {
            free(confList[deleNum].uname);
        }
        if (confList[deleNum].pwd != NULL) {
            free(confList[deleNum].pwd);
        }
        if (confList[deleNum].domain != NULL) {
            free(confList[deleNum].domain);
        }
        if (confList[deleNum].startApp != NULL) {
            free(confList[deleNum].startApp);
        }
        if (confList[deleNum].workDir != NULL) {
            free(confList[deleNum].workDir);
        }if (confList[deleNum].desc != NULL) {
            free(confList[deleNum].desc);
        }
    }
    close(ctl_sock);
    [pool drain];
    return 0;
}

