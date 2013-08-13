//
//  ViewController.m
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 7/12/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import "ViewController.h"
#import "IMSMemoryManager.h"

@interface ViewController ()

@end

@implementation ViewController

NSArray* arr;
NSString* str;
NSData* data;
NSNumber* num;

- (void)viewDidLoad
{
    [super viewDidLoad];

    unsigned char bytes[] = {4,9,5};
    data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    num = [[NSNumber alloc] initWithInt:495];
    str = [[NSString alloc] initWithFormat:@"Four Hundred Ninety Five"];
    
    arr = [[NSArray alloc] initWithObjects:data,num,str,nil];
    
    [self updateWidgets];
}

- (void)updateWidgets
{
    // TODO, consider wiping temp values
    [self.StrLabel setText:str];
    [self.StrHex setText:hexString(str)];
    [self.DataLabel setText:[NSString stringWithFormat: @"%@", data]];
    [self.DataHex setText:hexString(data)];
    [self.NumLabel setText:[NSString stringWithFormat: @"%@", num]];
    [self.NumHex setText:hexString(num)];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (IBAction)StrWipe:(id)sender {
    wipe(str);
    [self updateWidgets];
}

- (IBAction)StrLock:(id)sender {
    lock(str, @"PASS");
    [self updateWidgets];
}

- (IBAction)StrUnlock:(id)sender {
    unlock(str, @"PASS");
    [self updateWidgets];
}

- (IBAction)DataWipe:(id)sender {
    wipe(data);
    [self updateWidgets];
}

- (IBAction)DataLock:(id)sender {
    lock(data, @"PASS");
    [self updateWidgets];
}

- (IBAction)DataUnlock:(id)sender {
    unlock(data, @"PASS");
    [self updateWidgets];
}

- (IBAction)NumberWipe:(id)sender {
    wipe(num);
    [self updateWidgets];
}

- (IBAction)NumberLock:(id)sender{
    lock(num, @"PASS");
    [self updateWidgets];
}

- (IBAction)NumberUnlock:(id)sender {
    unlock(num, @"PASS");
    [self updateWidgets];    
}
@end
