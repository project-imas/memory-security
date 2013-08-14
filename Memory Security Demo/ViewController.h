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
@property (weak, nonatomic) IBOutlet UILabel *ArrayLabel;

@property (weak, nonatomic) IBOutlet UIButton *StrTrackButton;
@property (weak, nonatomic) IBOutlet UIButton *ArrTrackButton;
@property (weak, nonatomic) IBOutlet UIButton *DataTrackButton;
@property (weak, nonatomic) IBOutlet UIButton *NumTrackButton;

- (IBAction)StrWipe:(id)sender;
- (IBAction)StrLock:(id)sender;
- (IBAction)StrUnlock:(id)sender;
- (IBAction)StringTrack:(id)sender;

- (IBAction)DataWipe:(id)sender;
- (IBAction)DataLock:(id)sender;
- (IBAction)DataUnlock:(id)sender;
- (IBAction)DataTrack:(id)sender;

- (IBAction)NumberWipe:(id)sender;
- (IBAction)NumberLock:(id)sender;
- (IBAction)NumberUnlock:(id)sender;
- (IBAction)NumberTrack:(id)sender;

- (IBAction)ArrayWipe:(id)sender;
- (IBAction)ArrayLock:(id)sender;
- (IBAction)ArrayUnlock:(id)sender;
- (IBAction)ArrayTrack:(id)sender;

- (IBAction)WipeAll:(id)sender;
- (IBAction)LockAll:(id)sender;
- (IBAction)UnlockAll:(id)sender;
- (IBAction)ChecksumAll:(id)sender;


@end
