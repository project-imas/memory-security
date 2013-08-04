//
//  IMSHandler.h
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 8/2/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface IMSHandler : NSObject

typedef NS_ENUM(NSInteger, MemState) {
    IGNORE,
    LOCKED,
    UNLOCKED
};

+ (NSMutableDictionary*) pointers;

+ (BOOL) track:(NSObject *)obj;

+ (BOOL) wipe:(NSObject *)obj;
+ (BOOL) wipeAll;


@end
