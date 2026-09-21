//
//  AppGroup.m
//  iSH
//
//  Created by Theodore Dubois on 2/28/20.
//

#import "AppGroup.h"
#import <Foundation/Foundation.h>
#import <mach-o/ldsyms.h>
#import <mach-o/loader.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>

#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171

struct cs_blob_index {
    uint32_t type;
    uint32_t offset;
};

struct cs_superblob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    struct cs_blob_index index[];
};

struct cs_entitlements {
    uint32_t magic;
    uint32_t length;
    char entitlements[];
};

static NSDictionary *AppEntitlements(void) {
    static NSDictionary *entitlements;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
        const struct mach_header_64 *header = &_mh_execute_header;

        // Simulator executables have fake entitlements in the code signature.
        // The real entitlements can be found in an __entitlements section.
        size_t entitlements_size = 0;
        char *entitlements_data = (char *)getsectiondata(header, "__TEXT", "__entitlements", &entitlements_size);
        if (entitlements_data != NULL && entitlements_size != 0) {
            NSData *data = [NSData dataWithBytes:entitlements_data length:entitlements_size];
            entitlements = [NSPropertyListSerialization propertyListWithData:data
                                                                       options:NSPropertyListImmutable
                                                                        format:nil
                                                                         error:nil];
            return;
        }

        // LiveContainer and ad-hoc installations may not expose the original
        // application-group entitlement in the executable code signature.
        struct load_command *lc = (void *)(header + 1);
        struct linkedit_data_command *cs_lc = NULL;
        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (lc->cmd == LC_CODE_SIGNATURE) {
                cs_lc = (struct linkedit_data_command *)lc;
                break;
            }
            if (lc->cmdsize == 0)
                break;
            lc = (void *)((char *)lc + lc->cmdsize);
        }
        if (cs_lc == NULL)
            return;

        NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingFromURL:NSBundle.mainBundle.executableURL error:nil];
        if (fileHandle == nil)
            return;
        [fileHandle seekToFileOffset:cs_lc->dataoff];
        NSData *csData = [fileHandle readDataOfLength:cs_lc->datasize];
        [fileHandle closeFile];
        if (csData.length < sizeof(struct cs_superblob))
            return;

        const struct cs_superblob *cs = csData.bytes;
        if (ntohl(cs->magic) != CSMAGIC_EMBEDDED_SIGNATURE)
            return;
        uint32_t count = ntohl(cs->count);
        if (csData.length < sizeof(struct cs_superblob) + count * sizeof(struct cs_blob_index))
            return;

        for (uint32_t i = 0; i < count; i++) {
            uint32_t offset = ntohl(cs->index[i].offset);
            if (offset + sizeof(struct cs_entitlements) > csData.length)
                continue;
            struct cs_entitlements *ents = (void *)((char *)cs + offset);
            uint32_t length = ntohl(ents->length);
            if (ntohl(ents->magic) != CSMAGIC_EMBEDDED_ENTITLEMENTS ||
                length < offsetof(struct cs_entitlements, entitlements) ||
                offset + length > csData.length)
                continue;
            NSData *entitlementsData = [NSData dataWithBytes:ents->entitlements
                                                       length:length - offsetof(struct cs_entitlements, entitlements)];
            entitlements = [NSPropertyListSerialization propertyListWithData:entitlementsData
                                                                        options:NSPropertyListImmutable
                                                                         format:nil
                                                                          error:nil];
            break;
        }
    });
    return entitlements;
}

NSArray<NSString *> *CurrentAppGroups(void) {
    NSArray *groups = AppEntitlements()[@"com.apple.security.application-groups"];
    return [groups isKindOfClass:NSArray.class] ? groups : @[];
}

NSURL *ContainerURL(void) {
    NSString *appGroup = CurrentAppGroups().firstObject;
    NSURL *container = nil;
    if (appGroup.length != 0)
        container = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:appGroup];

    // LiveContainer commonly rewrites/removes application-group entitlements.
    // Keep the app usable by falling back to its private sandbox instead of
    // dereferencing a missing group or returning a nil root directory.
    if (container == nil) {
        NSURL *support = [NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory
                                                                inDomains:NSUserDomainMask].firstObject;
        container = [support URLByAppendingPathComponent:@"ios-linuxkit" isDirectory:YES];
        [NSFileManager.defaultManager createDirectoryAtURL:container
                               withIntermediateDirectories:YES
                                                attributes:nil
                                                     error:nil];
    }
    return container;
}
