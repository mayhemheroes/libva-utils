#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "tinyjpeg.h"


extern "C" struct jdec_private *tinyjpeg_init(void);
extern "C" void tinyjpeg_free(struct jdec_private *priv);
extern "C" int tinyjpeg_parse_header(struct jdec_private *priv, const unsigned char *buf, unsigned int size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 100) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    std::vector<unsigned char> vec = provider.ConsumeBytes<unsigned char>(100);
    jdec_private* jdec = tinyjpeg_init();

    tinyjpeg_parse_header(jdec, &vec[0], 100);

    tinyjpeg_free(jdec);

    return 0;
}
