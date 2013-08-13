//
//  ViewController.h
//  Memory Security Demo
//
//  Created by Black, Gavin S. on 7/12/13.
//  Copyright (c) 2013 Black, Gavin S. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController

@property (weak, nonatomic) IBOutlet UILabel *StrLabel;
@property (weak, nonatomic) IBOutlet UILabel *StrHex;
@property (weak, nonatomic) IBOutlet UILabel *DataLabel;
@property (weak, nonatomic) IBOutlet UILabel *DataHex;
@property (weak, nonatomic) IBOutlet UILabel *NumLabel;
@property (weak, nonatomic) IBOutlet UILabel *NumHex;

- (IBAction)StrWipe:(id)sender;
- (IBAction)StrLock:(id)sender;
- (IBAction)StrUnlock:(id)sender;

- (IBAction)DataWipe:(id)sender;
- (IBAction)DataLock:(id)sender;
- (IBAction)DataUnlock:(id)sender;

- (IBAction)NumberWipe:(id)sender;
- (IBAction)NumberLock:(id)sender;
- (IBAction)NumberUnlock:(id)sender;

@end
