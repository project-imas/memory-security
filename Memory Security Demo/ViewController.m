//
//  ViewController.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 7/12/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "ViewController.h"
#import "IMSHandler.h"

@interface ViewController ()

@end

@implementation ViewController


- (void)viewDidLoad
{
    [super viewDidLoad];
    NSString* str = [[NSString alloc] initWithFormat:@"TESTING111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"];
    [IMSHandler track:str];
    NSLog(@"NSString: %@", str);
   // [IMSHandler wipe:str];
   // [IMSHandler untrack:str];
   // [IMSHandler wipeAll];
    [IMSHandler lock:str:@"FASD"];
    [IMSHandler unlock:str:@"FASD"];
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
    
    
    [IMSHandler wipe:data];
    NSLog(@"NSData: %@", data);
  //  NSLog(@"OBJ MEM: %p, %zd", data, malloc_size(data));
    
    NSLog(@"ALL DONE");
 //   NSString *imsStr = (NSString *)[IMSObject alloc];
    
    
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
