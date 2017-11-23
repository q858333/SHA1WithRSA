//
//  ViewController.m
//  RSAWithSHA1
//
//  Created by dengbin on 2017/11/23.
//  Copyright © 2017年 dengbin. All rights reserved.
//

#import "ViewController.h"
#import "RSA.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    NSString *string = @"123";
    NSString *sign = [RSA signTheDataSHA1WithRSA:string];
    NSLog(@"签名----%@",sign);

    //返回1表示验签成功
    NSLog(@"验签-----%d",[RSA verifyBytesSHA1WithRSA:string signature:sign]);
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
