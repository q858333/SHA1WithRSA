//
//  RSA.m
//  rsSDK
//
//  Created by ycw on 2017/11/2.
//

#import "RSA.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>

#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH  // SHA-1消息摘要的数据位数160位


@implementation RSA


#pragma mark - SHA1+RSA 签名
+ (NSString *)signSHA1WithRSA:(NSString *)plainText{
    uint8_t* signedBytes = NULL;
    size_t signedBytesSize = 0;
    OSStatus sanityCheck = noErr;
    NSData* signedHash = nil;

    NSString * path = [[NSBundle mainBundle]pathForResource:@"private_key" ofType:@"p12"];
    NSData * data = [NSData dataWithContentsOfFile:path];
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init]; // Set the private key query dictionary.
    [options setObject:@"js" forKey:(id)kSecImportExportPassphrase];//密码
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((CFDataRef) data, (CFDictionaryRef)options, &items);
    if (securityError!=noErr) {
        return nil ;
    }
    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identityApp =(SecIdentityRef)CFDictionaryGetValue(identityDict,kSecImportItemIdentity);
    SecKeyRef privateKeyRef=nil;
    SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
    signedBytesSize = SecKeyGetBlockSize(privateKeyRef);

    NSData *plainTextBytes = [plainText dataUsingEncoding:NSUTF8StringEncoding];

    signedBytes = malloc( signedBytesSize * sizeof(uint8_t) ); // Malloc a buffer to hold signature.
    memset((void  *)signedBytes, 0x0, signedBytesSize);

    sanityCheck = SecKeyRawSign(privateKeyRef,
                                kSecPaddingPKCS1SHA1,
                                (const uint8_t *)[[self getHashBytes:plainTextBytes] bytes],
                                kChosenDigestLength,
                                (uint8_t *)signedBytes,
                                &signedBytesSize);

    if (sanityCheck == noErr){
        signedHash = [NSData dataWithBytes:(const void  *)signedBytes length:(NSUInteger)signedBytesSize];
    }
    else{
        return nil;
    }


    if (signedBytes){
        free(signedBytes);
    }


    NSString *signatureResult = [self base64EncodeData:signedHash];
    //    NSString *signatureResult=[NSString stringWithFormat:@"%@",base64_encode_data(signedHash)];
    return signatureResult;
}
+ (NSData *)getHashBytes:(NSData *)plainText {
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;

    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void  *)hashBytes, 0x0, kChosenDigestLength);
    // Initialize the context.
    CC_SHA1_Init(&ctx);
    // Perform the hash.
    CC_SHA1_Update(&ctx, (void  *)[plainText bytes], [plainText length]);
    // Finalize the output.
    CC_SHA1_Final(hashBytes, &ctx);

    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void  *)hashBytes length:(NSUInteger)kChosenDigestLength];
    if (hashBytes) free(hashBytes);


    return hash;
}
#pragma mark - SHA1+RSA 验签
+ (BOOL)verifySHA1WithRSA:(NSString *)plainString signature:(NSString *)signatureString{

    NSData *plainData = [plainString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [self base64DecodeString:signatureString];
    SecKeyRef publicKey = [self getPublicKey];
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signatureData bytes];

    size_t hashBytesSize = CC_SHA1_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA1([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return NO;
    }

    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1SHA1,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);

    return status == errSecSuccess;
}

+ (SecKeyRef)getPublicKey {
    NSString * path = [[NSBundle mainBundle]pathForResource:@"public_key" ofType:@"der"];
    NSData * derData = [NSData dataWithContentsOfFile:path];

    SecCertificateRef myCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)derData);
    SecPolicyRef myPolicy = SecPolicyCreateBasicX509();
    SecTrustRef myTrust;
    OSStatus status = SecTrustCreateWithCertificates(myCertificate,myPolicy,&myTrust);
    SecTrustResultType trustResult;
    if (status == noErr) { status = SecTrustEvaluate(myTrust, &trustResult); }
    SecKeyRef securityKey = SecTrustCopyPublicKey(myTrust);
    CFRelease(myCertificate); CFRelease(myPolicy);
    CFRelease(myTrust);



    //    SecIdentityRef myIdentity;
    //    SecTrustRef myTrust;
    //    extractIdentityAndTrust((__bridge CFDataRef)data, &myIdentity, &myTrust);
    //
    //    SecKeyRef publicKey;
    //    publicKey = SecTrustCopyPublicKey(myTrust);

    return securityKey;
}
//OSStatus extractIdentityAndTrust(CFDataRef inP12data, SecIdentityRef *identity, SecTrustRef *trust)
//{
//    OSStatus securityError = errSecSuccess;
//
//    CFStringRef password = CFSTR("");
//    const void *keys[] = { kSecImportExportPassphrase };
//    const void *values[] = { password };
//
//    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
//
//    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
//    securityError = SecPKCS12Import(inP12data, options, &items);
//
//    if (securityError == 0) {
//        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
//        const void *tempIdentity = NULL;
//        tempIdentity = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
//        *identity = (SecIdentityRef)tempIdentity;
//        const void *tempTrust = NULL;
//        tempTrust = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
//        *trust = (SecTrustRef)tempTrust;
//    }
//
//    if (options) {
//        CFRelease(options);
//    }
//
//    return securityError;
//}
#pragma mark - Base64
+ (NSString *)base64EncodeData:(NSData *)data{
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}
+ (NSData *)base64DecodeString:(NSString *)string{

    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}


@end
