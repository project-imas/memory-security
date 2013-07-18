//
//  ViewController.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 7/12/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController


+ (void) wipeObject:(NSObject*) obj
{
    if([obj isKindOfClass:[NSString class]]) {
        NSString* str = (NSString*)obj;
        unsigned char* strPtr = (unsigned char *) CFStringGetCStringPtr((CFStringRef) str, CFStringGetSystemEncoding());
        memset(strPtr, 0, [str length]);
        /* Why can't you reliably test encodings?
         if(![str canBeConvertedToEncoding:(NSUTF8StringEncoding)]) {
          unsigned char* strPtr16 = (unsigned char *) CFStringGetCharactersPtr((CFStringRef) str);
          memset(strPtr16, 0, [str length]);
        }*/
    } else if([obj isKindOfClass:[NSData class]]) {
        NSData* data = (NSData*)obj;
        memset([data bytes], 0, [data length]);
    } else {
        NSLog(@"Wiping of object type not supported!");
    }

}

- (void)viewDidLoad
{
    [super viewDidLoad];
    NSString* str = [[NSString alloc] initWithFormat:@"TESTING"];
   
    NSLog(@"NSString: %@", str);
    [ViewController wipeObject:str];
    NSLog(@"NSString: %@", str);

    /*
    NSData *strData = [@"UTF16 TEST" dataUsingEncoding:NSUTF16StringEncoding];
    NSString *str16 = [[NSString alloc] initWithData:strData encoding:NSUTF16LittleEndianStringEncoding];
    
    NSLog(@"UTF16: %@", str16);
    [ViewController wipeObject:str16];
    NSLog(@"UTF16: %@", str16);
    */
    
    unsigned char bytes[] = {4,9,5};
    NSData *data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    NSLog(@"NSData: %@", data);
    [ViewController wipeObject:data];
    NSLog(@"NSData: %@", data);
    
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
