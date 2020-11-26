//
//  Created by Patrick Hogan/Manuel Zamora 2012
//


////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark - Public Interface
////////////////////////////////////////////////////////////////////////////////////////////////////////////
#import <Foundation/Foundation.h>
#import "BDError.h"
#import "BDLog.h"
@interface NSArray (BDJSONSerialization)

- (NSString *)stringValue:(BDError *)error;
- (NSData *)dataValue:(BDError *)error;

@end
