#include "float-helpers.h"

#include <math.h>

bool isclose(float a, float b)
{
    const float rel_tol = 2.5e-4f;

    const float comp = (fabs(a) < fabs(b) ? fabs(b) : fabs(a));

    return fabs(a - b) <= (rel_tol * comp);
}
