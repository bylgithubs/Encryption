//
//  SCRSACryptor.h
//  SmartCity
//
//  Created by hoperun on 15/11/12.
//  Copyright (c) 2015年 sea. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SCRSACryptor : NSObject
/*
 *  @brief 初始化
 *
 *  @param privateKey：私钥  publicKey：公钥
 *  
 *  @return id
 */
- (id)initWithPrivateKey:(NSString *)privateKey publicKey:(NSString *)publicKey;
/*
 *  @brief 解密
 *
 *  @param 用公钥加密的密文
 *
 */
- (NSString *)decryptString:(NSString *)ciphertext;
/*
 *  @brief 加密
 *
 *  @param 需要用公钥加密的明文
 *
 */
- (NSString *)encryptString:(NSString *)expressText;
@end
