#include <complex>

void xcorr(std::complex<float> *x0, std::complex<float> *x1, std::complex<float> *y, uint64_t N);
int64_t xcorr_lag(std::complex<float> *xcorr, uint64_t N);
