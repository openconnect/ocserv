#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <libtasn1.h>

const asn1_static_node kkdcp_asn1_tab[] = {
  { "KKDCP", 536872976, NULL },
  { NULL, 1073741836, NULL },
  { "KDC-PROXY-MESSAGE", 536870917, NULL },
  { "kerb-message", 1610620935, NULL },
  { NULL, 2056, "0"},
  { "target-domain", 1610637339, NULL },
  { NULL, 2056, "1"},
  { "dclocator-hint", 536895491, NULL },
  { NULL, 2056, "2"},
  { NULL, 0, NULL }
};
