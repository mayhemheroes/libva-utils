#include <stddef.h>
#include <stdint.h>

#include "tinyjpeg.h"

extern "C" struct jdec_private *tinyjpeg_init(void);
extern "C" void tinyjpeg_free(struct jdec_private *priv);
extern "C" int tinyjpeg_parse_header(struct jdec_private *priv,
                                     const unsigned char *buf, unsigned int size);
extern "C" void tinyjpeg_get_size(struct jdec_private *priv,
                                  unsigned int *width, unsigned int *height);

// In-process harness for the `loadjpeg` decode CLI.
//
// The upstream `loadjpeg` binary is a raw file-input tool (loadjpeg.c::convert_one_image):
// it reads a file, then runs tinyjpeg_init -> tinyjpeg_parse_header -> tinyjpeg_get_size ->
// tinyjpeg_decode. Only tinyjpeg_decode() needs a live VAAPI display (va_open_display +
// vaInitialize), which is unavailable in a headless CI/commit container, so every input
// dead-ends identically at vaInitialize and the ASan-instrumented CLI yields 0 coverage
// edges under Mayhem. Per the porting policy for unfuzzable raw-file CLIs, we drive the same
// pre-decode code path in-process here (the exact sequence convert_one_image runs before it
// touches VAAPI), giving coverage-guided, ASan-instrumented fuzzing of the JPEG header/marker
// parser that loadjpeg feeds. Target name `loadjpeg` is preserved for run-history continuity.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // convert_one_image over-allocates by 4 bytes; tinyjpeg_parse_header always touches the
    // first two bytes before consulting `size`, so require at least that much.
    if (size < 2)
        return 0;

    struct jdec_private *jdec = tinyjpeg_init();
    if (jdec == NULL)
        return 0;

    if (tinyjpeg_parse_header(jdec, data, (unsigned int)size) >= 0) {
        unsigned int width = 0, height = 0;
        tinyjpeg_get_size(jdec, &width, &height);
    }

    tinyjpeg_free(jdec);
    return 0;
}
