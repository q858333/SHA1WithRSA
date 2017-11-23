//
//  RSA.h
//  rsSDK
//
//  Created by ycw on 2017/11/2.
//

#import <Foundation/Foundation.h>

@interface RSA : NSObject

/**
 *  SHA1+RSA 签名
 *
 *  @return string
 */
+ (NSString *)signTheDataSHA1WithRSA:(NSString *)plainText;

/**
 *  SHA1+RSA 验签
 *
 *  @return bool
 */
+ (BOOL)verifyBytesSHA1WithRSA:(NSString *)plainString signature:(NSString *)signatureString;

@end
