#include "xcorr.h"

void xcorr(std::complex<float> *x0, std::complex<float> *x1, std::complex<float> *y, uint64_t N)
{
  // Calculate cross-correlation between input signals x0 and x1 and store
  // result in y. Used for time-alignment of the 4 MSR4 channels.
  uint64_t k, l;
  int64_t i;

  for (k = 0; k < (2 * N - 1); k++)
  {
    y[k] = std::complex<float>(0.0, 0.0);
    for (l = 0; l < N; l++)
    {
      i = l - k + N - 1;
      if (i < 0 || i >= N)
        continue;
      y[k] += x0[l] * std::conj<float>(x1[i]);
    }
  }
}

int64_t xcorr_lag(std::complex<float> *xcorr, uint64_t N)
{
  // Calculate time lag (in samples) between two input signals based on their
  // cross-correlation data.
  uint64_t k_max;
  float abs, abs_max;
  int64_t lag;

  for (uint64_t k = 0; k < (2 * N - 1); k++)
  {
    abs = std::abs<float>(xcorr[k]);

    if (k == 0 || abs > abs_max)
    {
      k_max = k;
      abs_max = abs;
    }
  }

  lag = (int64_t)k_max - (int64_t)N + 1;

  if (lag < -((int64_t)N) / 2)
    lag += (int64_t)N;
  else if(lag > ((int64_t)N) /2)
    lag -= (int64_t)N;

  return lag;
}
