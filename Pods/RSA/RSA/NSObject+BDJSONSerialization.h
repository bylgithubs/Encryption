//
//  Created by Patrick Hogan/Manuel Zamora 2012
//


////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark - Public Interface
////////////////////////////////////////////////////////////////////////////////////////////////////////////
#import <Foundation/Foundation.h>
#import "BDError.h"
#import "BDLog.h"
@interface NSObject (BDJSONSerialization)

- (NSData *)dataValue:(BDError *)error;
- (NSString *)stringValue:(BDError *)error;
- (NSMutableDictionary *)JSONObject:(BDError *)error;
- (NSMutableArray *)JSONArray:(BDError *)error;

@end