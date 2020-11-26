//
//  RSAEncrypt.m
//  Encryption
//
//  Created by Civet on 2020/11/24.
//  Copyright © 2020 PersonalONBYL. All rights reserved.
//

#import "RSAEncrypt.h"
#import <MF_Base64Additions.h>

@implementation RSAEncrypt

/****************************RSAEncrypt.m类实现文件内容****************************/
#pragma mark - Class Utils Method
+ (BOOL)isEmptyKeyRef:(id)object
{
    if (object == nil) {
        return YES;
    } else if (object == NULL) {
        return YES;
    } else if (object == [NSNull null]) {
        return YES;
    }
    NSData *data = [NSData dataWithContentsOfFile:@""];
    NSData *base64Data = [data base64EncodedDataWithOptions:0];
    [base64Data writeToFile:@"" atomically:YES];
    
    NSData *base64Data1 = [NSData dataWithContentsOfFile:@""];
    NSData *baseData = [[NSData alloc] initWithBase64EncodedData:base64Data1 options:0];
    [baseData writeToFile:@"" atomically:YES];
    return NO;
}


#pragma mark - Private Method
+ (SecKeyRef)getPrivateKeyRefWithFilePath:(NSString *)filePath keyPassword:(NSString *)keyPassword
{
    //读取私钥证书文件的内容
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    if ((certificateData == nil) || (certificateData == NULL)) {
        return nil;
    } else if (![certificateData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([certificateData length] <= 0) {
        return nil;
    }
    
    //拼接密码参数到字典中
    NSString *passwordKey = (__bridge id)kSecImportExportPassphrase;
    NSString *passwordValue = [NSString stringWithFormat:@"%@",keyPassword];
    if ((keyPassword == nil) || (keyPassword == NULL)) {
        passwordValue = @"";
    } else if (![keyPassword isKindOfClass:[NSString class]]) {
        passwordValue = @"";
    } else if ([keyPassword length] <= 0) {
        passwordValue = @"";
    }
    NSMutableDictionary *optionInfo = [[NSMutableDictionary alloc] init];
    [optionInfo setObject:passwordValue forKey:passwordKey];
    
    //获取私钥对象
    SecKeyRef privateKeyRef = NULL;
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    CFDataRef pkcs12Data = (__bridge CFDataRef)certificateData;
    CFDictionaryRef options = (__bridge CFDictionaryRef)optionInfo;
    OSStatus securityStatus = SecPKCS12Import(pkcs12Data, options, &items);
    if (securityStatus == noErr && CFArrayGetCount(items) > 0)
    {
        SecIdentityRef identity;
        const void *secpkey = kSecImportItemIdentity;
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        identity = (SecIdentityRef)CFDictionaryGetValue(identityDict,secpkey);
        securityStatus = SecIdentityCopyPrivateKey(identity, &privateKeyRef);
        if (securityStatus != noErr)
        {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    return privateKeyRef;
}

+ (SecKeyRef)privateKeyRefWithPrivateKey:(NSString *)privateKey
{
    //判断参数是否正确
    if ((privateKey == nil) || (privateKey == NULL)) {
        return nil;
    } else if (![privateKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKey length] <= 0) {
        return nil;
    }
    
    //解析私钥对象内容
    NSString *pKey = [NSString stringWithFormat:@"%@",privateKey];
    NSRange sposition = [pKey rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    NSRange eposition = [pKey rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    if (sposition.location != NSNotFound && eposition.location != NSNotFound)
    {
        NSUInteger endposition = eposition.location;
        NSUInteger startposition = sposition.location + sposition.length;
        NSRange range = NSMakeRange(startposition, endposition-startposition);
        pKey = [pKey substringWithRange:range];
    }
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    //This will be base64 encoded, decode it.
//    NSData *keyData = [Base64 base64DecodeDataWithString:pKey];
    NSData *keyData = [MF_Base64Codec dataFromBase64String:pKey];
    keyData = [self stripPrivateKeyHeader:keyData];
    if ((keyData == nil) || (keyData == NULL)) {
        return nil;
    } else if (![keyData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([keyData length] <= 0) {
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PrivKey";
    const void *bytes = [tag UTF8String];
    NSData *tagData = [NSData dataWithBytes:bytes length:[tag length]];
    
    //Delete any old lingering key with the same tag
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassKey
                   forKey:(__bridge id)kSecClass];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:tagData
                   forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)attributes);
    
    //Add persistent version of the key to system keychain
    [attributes setObject:keyData forKey:(__bridge id)kSecValueData];
    [attributes setObject:(__bridge id)kSecAttrKeyClassPrivate
                   forKey:(__bridge id)kSecAttrKeyClass];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus status = noErr;
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)attributes, &persistKey);
    if (persistKey != nil) {CFRelease(persistKey);}
    if ((status != noErr) && (status != errSecDuplicateItem))
    {
        return nil;
    }
    
    [attributes removeObjectForKey:(__bridge id)kSecValueData];
    [attributes removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnRef];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    
    //Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    CFDictionaryRef query = (__bridge CFDictionaryRef)attributes;
    status = SecItemCopyMatching(query, (CFTypeRef *)&keyRef);
    if (status != noErr)
    {
        return nil;
    }
    return keyRef;
}

+ (NSData *)stripPrivateKeyHeader:(NSData *)d_key
{
    //Skip ASN.1 private key header
    if (d_key == nil) return nil;
    
    unsigned long len = [d_key length];
    if (!len) return nil;
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 22; //magic byte at offset 22
    
    if (0x04 != c_key[idx++]) return nil;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    if (!(c_len & 0x80))
    {
        c_len = c_len & 0x7f;
    }
    else
    {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    //Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

+ (SecKeyRef)getPublicKeyRefWithFilePath:(NSString *)filePath
{
    //读取公钥证书文件的内容
    NSData *certificateData = [NSData dataWithContentsOfFile:filePath];
    if ((certificateData == nil) || (certificateData == NULL)) {
        return nil;
    } else if (![certificateData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([certificateData length] <= 0) {
        return nil;
    }
    
    //将公钥证书制作成证书对象
    CFDataRef data = (__bridge CFDataRef)certificateData;
    SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, data);
    
    //获取公钥对象
    SecTrustRef trust = NULL;
    SecKeyRef publicKey = NULL;
    SecPolicyRef policies = SecPolicyCreateBasicX509();
    if (![[self class] isEmptyKeyRef:(__bridge id)(certificateRef)]
        && ![[self class] isEmptyKeyRef:(__bridge id)(policies)])
    {
        OSStatus status;
        status = SecTrustCreateWithCertificates((CFTypeRef)certificateRef,
                                                policies, &trust);
        if (status == noErr)
        {
            SecTrustResultType result;
            if (SecTrustEvaluate(trust, &result) == noErr)
            {
                publicKey = SecTrustCopyPublicKey(trust);
            }
        }
    }
    if (certificateRef != NULL) CFRelease(certificateRef);
    if (policies != NULL) CFRelease(policies);
    if (trust != NULL) CFRelease(trust);
    return publicKey;
}

+ (SecKeyRef)publicKeyRefWithPublicKey:(NSString *)publicKey
{
    //判断参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }
    
    //解析公钥对象内容
    NSString *pKey = [NSString stringWithFormat:@"%@",publicKey];
    NSRange sposition = [pKey rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange eposition = [pKey rangeOfString:@"-----END PUBLIC KEY-----"];
    if (sposition.location != NSNotFound && eposition.location != NSNotFound)
    {
        NSUInteger startposition = eposition.location;
        NSUInteger endposition = sposition.location + sposition.length;
        NSRange range = NSMakeRange(endposition, startposition-endposition);
        pKey = [pKey substringWithRange:range];
    }
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    pKey = [pKey stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    //This will be base64 encoded, decode it.
//    NSData *keyData = [[self class] base64DecodeDataWithString:pKey];
    NSData *keyData = [MF_Base64Codec dataFromBase64String:pKey];
    keyData = [self stripPublicKeyHeader:keyData];
    if ((keyData == nil) || (keyData == NULL)) {
        return nil;
    } else if (![keyData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([keyData length] <= 0) {
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    const void *bytes = [tag UTF8String];
    NSData *tagData = [NSData dataWithBytes:bytes length:[tag length]];
    
    //Delete any old lingering key with the same tag
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassKey
                   forKey:(__bridge id)kSecClass];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:tagData
                   forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)attributes);
    
    //Add persistent version of the key to system keychain
    [attributes setObject:keyData
                   forKey:(__bridge id)kSecValueData];
    [attributes setObject:(__bridge id)kSecAttrKeyClassPublic
                   forKey:(__bridge id)kSecAttrKeyClass];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus status = noErr;
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)attributes, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    if ((status != noErr) && (status != errSecDuplicateItem))
    {
        return nil;
    }
    [attributes removeObjectForKey:(__bridge id)kSecValueData];
    [attributes removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnRef];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    
    //Now fetch the SecKeyRef version of the key
    SecKeyRef publicKeyRef = nil;
    CFDictionaryRef query = (__bridge CFDictionaryRef)attributes;
    status = SecItemCopyMatching(query, (CFTypeRef *)&publicKeyRef);
    if (status != noErr)
    {
        return nil;
    }
    return publicKeyRef;
}

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    //Skip ASN.1 public key header
    if (d_key == nil) {return nil;}
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 0;
    if (c_key[idx++] != 0x30) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx++;
    }
    
    //PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] = {0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01, 0x05, 0x00};
    if (memcmp(&c_key[idx], seqiod, 15)) {return nil;}
    idx += 15;
    if (c_key[idx++] != 0x03) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx ++;
    }
    if (c_key[idx++] != '\0') {return nil;}
    
    //Now make a new NSData from this buffer
    return ([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef, kSecPaddingPKCS1,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            [ret appendBytes:outbuf length:outlen];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size)
        {
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef, kSecPaddingNone,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for (int i = 0; i < outlen; i ++)
            {
                if (outbuf[i] == 0)
                {
                    if (idxFirstZero < 0)
                    {
                        idxFirstZero = i;
                    }
                    else
                    {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            NSUInteger length = idxNextZero-idxFirstZero-1;
            [ret appendBytes:&outbuf[idxFirstZero+1] length:length];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}


#pragma mark - RSA Key File Encrypt/Decrypt Public Method
+ (NSString *)encryptString:(NSString *)originString publicKeyPath:(NSString *)publicKeyPath
{
    //判断originString参数是否正确
    if ((originString == nil) || (originString == NULL)) {
        return nil;
    } else if (![originString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([originString length] <= 0) {
        return nil;
    }
    
    //判断publicKeyPath参数是否正确
    if ((publicKeyPath == nil) || (publicKeyPath == NULL)) {
        return nil;
    } else if (![publicKeyPath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKeyPath length] <= 0) {
        return nil;
    }
    
    //获取公钥对象和需要加密的字符串内容编码数据流
    SecKeyRef publicKeyRef = [self getPublicKeyRefWithFilePath:publicKeyPath];
    NSData *originData = [originString dataUsingEncoding:NSUTF8StringEncoding];
    if ([[self class] isEmptyKeyRef:(__bridge id)(publicKeyRef)]) {
        return nil;
    }
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }
    
    //加密源字符串内容编码数据流的数据
    NSData *resultData = nil;
    resultData = [self encryptData:originData withKeyRef:publicKeyRef];
//    return [[self class] base64EncodedStringWithData:resultData];
    return [MF_Base64Codec base64StringFromData:resultData];
}

+ (NSString *)decryptString:(NSString *)encryptString privateKeyPath:(NSString *)privateKeyPath privateKeyPwd:(NSString *)privateKeyPwd
{
    //判断encryptString参数是否正确
    if ((encryptString == nil) || (encryptString == NULL)) {
        return nil;
    } else if (![encryptString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([encryptString length] <= 0) {
        return nil;
    }
    
    //判断publicKeyPath参数是否正确
    if ((privateKeyPath == nil) || (privateKeyPath == NULL)) {
        return nil;
    } else if (![privateKeyPath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKeyPath length] <= 0) {
        return nil;
    }
    
    //判断密码是否存在
    NSString *keyPassword = [NSString stringWithFormat:@"%@",privateKeyPwd];
    if ((privateKeyPwd == nil) || (privateKeyPwd == NULL)) {
        keyPassword = @"";
    } else if (![privateKeyPwd isKindOfClass:[NSString class]]) {
        keyPassword = @"";
    } else if ([privateKeyPwd length] <= 0) {
        keyPassword = @"";
    }
    
    //获取私钥对象和需要加密的字符串内容编码数据流
    NSData *encryptData = nil, *decryptData = nil;
    SecKeyRef privateKeyRef = [self getPrivateKeyRefWithFilePath:privateKeyPath
                                                     keyPassword:privateKeyPwd];
//    encryptData = [[self class] base64DecodeDataWithString:encryptString];
    encryptData = [MF_Base64Codec dataFromBase64String:encryptString];
    if ([[self class] isEmptyKeyRef:(__bridge id)(privateKeyRef)]) {
        return nil;
    }
    if ((encryptData == nil) || (encryptData == NULL)) {
        return nil;
    } else if (![encryptData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([encryptData length] <= 0) {
        return nil;
    }
    NSStringEncoding encoding = NSUTF8StringEncoding;
    decryptData = [self decryptData:encryptData withKeyRef:privateKeyRef];
    return [[NSString alloc] initWithData:decryptData encoding:encoding];
}


#pragma mark - RSA Key String Encrypt/Decrypt Public Method
+ (NSData *)encryptData:(NSData *)originData publicKey:(NSString *)publicKey
{
    //判断originData参数是否正确
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }
    
    //判断publicKeyPath参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }
    
    //获取需要加密的字符串内容编码数据流
    SecKeyRef publicKeyRef = [self publicKeyRefWithPublicKey:publicKey];
    if([[self class] isEmptyKeyRef:(__bridge id)(publicKeyRef)]){
        return nil;
    }
    return [self encryptData:originData withKeyRef:publicKeyRef];
}

+ (NSString *)encryptString:(NSString *)originString publicKey:(NSString *)publicKey
{
    //判断publicKey参数是否正确
    if ((publicKey == nil) || (publicKey == NULL)) {
        return nil;
    } else if (![publicKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([publicKey length] <= 0) {
        return nil;
    }
    
    //判断originString参数是否正确
    if ((originString == nil) || (originString == NULL)) {
        return nil;
    } else if (![originString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([originString length] <= 0) {
        return nil;
    }
    
    //获取需要加密的字符串内容编码数据流
    NSData *originData = nil, *encryptData = nil;
    SecKeyRef publicKeyRef = [self publicKeyRefWithPublicKey:publicKey];
    originData = [originString dataUsingEncoding:NSUTF8StringEncoding];
    if([[self class] isEmptyKeyRef:(__bridge id)(publicKeyRef)]){
        return nil;
    }
    if ((originData == nil) || (originData == NULL)) {
        return nil;
    } else if (![originData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([originData length] <= 0) {
        return nil;
    }
    encryptData = [self encryptData:originData withKeyRef:publicKeyRef];
//    return [[self class] base64EncodedStringWithData:encryptData];
    return [MF_Base64Codec base64StringFromData:encryptData];
}

+ (NSString *)decryptString:(NSString *)encryptString privateKey:(NSString *)privateKey
{
    //判断publicKey参数是否正确
    if ((privateKey == nil) || (privateKey == NULL)) {
        return nil;
    } else if (![privateKey isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([privateKey length] <= 0) {
        return nil;
    }
    
    //判断originString参数是否正确
    if ((encryptString == nil) || (encryptString == NULL)) {
        return nil;
    } else if (![encryptString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([encryptString length] <= 0) {
        return nil;
    }
    
    //获取私钥对象和需要加密的字符串内容编码数据流
    SecKeyRef privateKeyRef;
    NSData *encryptData = nil, *decryptData = nil;
    privateKeyRef = [[self class] privateKeyRefWithPrivateKey:privateKey];
//    encryptData = [[self class] base64DecodeDataWithString:encryptString];
    encryptData = [MF_Base64Codec dataFromBase64String:encryptString];
    if ([[self class] isEmptyKeyRef:(__bridge id)(privateKeyRef)]) {
        return nil;
    }
    if ((encryptData == nil) || (encryptData == NULL)) {
        return nil;
    } else if (![encryptData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([encryptData length] <= 0) {
        return nil;
    }
    NSStringEncoding encoding = NSUTF8StringEncoding;
    decryptData = [self decryptData:encryptData withKeyRef:privateKeyRef];
    return [[NSString alloc] initWithData:decryptData encoding:encoding];
}
/******************************************************************************/


@end
