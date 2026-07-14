#include "hisi_wpa_hostap_compat.h"

enum length_modifier {
    LENGTH_DEFAULT,
    LENGTH_LONG,
    LENGTH_LONG_LONG,
    LENGTH_SIZE,
};

struct output {
    char *buffer;
    size_t size;
    size_t count;
};

static void output_char(struct output *output, char value)
{
    if (output->buffer != NULL && output->size != 0 &&
        output->count < output->size - 1)
        output->buffer[output->count] = value;
    output->count++;
}

static void output_repeat(struct output *output, char value, size_t count)
{
    while (count-- != 0)
        output_char(output, value);
}

static void output_finish(struct output *output)
{
    size_t index;
    if (output->buffer == NULL || output->size == 0)
        return;
    index = output->count < output->size - 1 ? output->count :
        output->size - 1;
    output->buffer[index] = '\0';
}

static int digit_value(int value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'z')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'Z')
        return value - 'A' + 10;
    return -1;
}

int hisi_wpa_isspace(int value)
{
    return value == ' ' || value == '\t' || value == '\n' ||
        value == '\r' || value == '\f' || value == '\v';
}

int hisi_wpa_isblank(int value)
{
    return value == ' ' || value == '\t';
}

int hisi_wpa_abs(int value)
{
    return value < 0 ? -value : value;
}

long hisi_wpa_strtol(const char *restrict value, char **restrict end, int base)
{
    const char *cursor = value;
    unsigned long result = 0;
    unsigned long limit;
    int negative = 0;
    int any = 0;

    while (hisi_wpa_isspace((unsigned char) *cursor))
        cursor++;
    if (*cursor == '-' || *cursor == '+') {
        negative = *cursor == '-';
        cursor++;
    }
    if (base == 0) {
        if (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X') &&
            digit_value((unsigned char) cursor[2]) >= 0) {
            base = 16;
            cursor += 2;
        } else if (cursor[0] == '0') {
            base = 8;
        } else {
            base = 10;
        }
    } else if (base == 16 && cursor[0] == '0' &&
        (cursor[1] == 'x' || cursor[1] == 'X') &&
        digit_value((unsigned char) cursor[2]) >= 0) {
        cursor += 2;
    }
    if (base < 2 || base > 36) {
        if (end != NULL)
            *end = (char *) value;
        return 0;
    }

    limit = negative ? (unsigned long) LONG_MAX + 1u :
        (unsigned long) LONG_MAX;
    for (;;) {
        int digit = digit_value((unsigned char) *cursor);
        if (digit < 0 || digit >= base)
            break;
        any = 1;
        if (result > (limit - (unsigned long) digit) /
            (unsigned long) base) {
            result = limit;
            do {
                cursor++;
                digit = digit_value((unsigned char) *cursor);
            } while (digit >= 0 && digit < base);
            break;
        }
        result = result * (unsigned long) base + (unsigned long) digit;
        cursor++;
    }
    if (end != NULL)
        *end = (char *) (any ? cursor : value);
    if (negative) {
        if (result == (unsigned long) LONG_MAX + 1u)
            return LONG_MIN;
        return -(long) result;
    }
    return (long) result;
}

int hisi_wpa_atoi(const char *value)
{
    return (int) hisi_wpa_strtol(value, NULL, 10);
}

static void swap_bytes(unsigned char *left, unsigned char *right, size_t size)
{
    while (size-- != 0) {
        unsigned char temporary = *left;
        *left++ = *right;
        *right++ = temporary;
    }
}

void hisi_wpa_qsort(void *base, size_t count, size_t size,
    int (*compare)(const void *left, const void *right))
{
    unsigned char *bytes = base;
    size_t index;
    if (bytes == NULL || compare == NULL || size == 0)
        return;
    for (index = 1; index < count; index++) {
        size_t position = index;
        while (position != 0) {
            unsigned char *left = bytes + (position - 1) * size;
            unsigned char *right = left + size;
            if (compare(left, right) <= 0)
                break;
            swap_bytes(left, right, size);
            position--;
        }
    }
}

static int parse_unsigned(const char **input, unsigned int *value)
{
    const char *cursor = *input;
    unsigned int result = 0;
    int any = 0;
    while (*cursor >= '0' && *cursor <= '9') {
        unsigned int digit = (unsigned int) (*cursor - '0');
        if (result > (UINT_MAX - digit) / 10u)
            result = UINT_MAX;
        else
            result = result * 10u + digit;
        any = 1;
        cursor++;
    }
    if (!any)
        return 0;
    *input = cursor;
    *value = result;
    return 1;
}

int hisi_wpa_sscanf(const char *input, const char *format, ...)
{
    const char expected[] = "%u:%u";
    const char *cursor = input;
    unsigned int first;
    unsigned int second;
    unsigned int *first_output;
    unsigned int *second_output;
    va_list arguments;
    size_t index;

    if (input == NULL || format == NULL)
        return EOF;
    for (index = 0; expected[index] != '\0'; index++) {
        if (format[index] != expected[index])
            return EOF;
    }
    if (format[index] != '\0' || !parse_unsigned(&cursor, &first))
        return 0;
    va_start(arguments, format);
    first_output = va_arg(arguments, unsigned int *);
    second_output = va_arg(arguments, unsigned int *);
    *first_output = first;
    if (*cursor != ':') {
        va_end(arguments);
        return 1;
    }
    cursor++;
    if (!parse_unsigned(&cursor, &second)) {
        va_end(arguments);
        return 1;
    }
    *second_output = second;
    va_end(arguments);
    return 2;
}

static size_t string_length_limit(const char *string, size_t limit)
{
    size_t length = 0;
    while (length < limit && string[length] != '\0')
        length++;
    return length;
}

static size_t unsigned_digits(char *reversed, uint64_t value,
    unsigned int base, int uppercase)
{
    const char *digits = uppercase ? "0123456789ABCDEF" :
        "0123456789abcdef";
    size_t count = 0;
    do {
        reversed[count++] = digits[value % base];
        value /= base;
    } while (value != 0);
    return count;
}

static void output_string(struct output *output, const char *string,
    size_t length, int width, int left)
{
    size_t padding = width > 0 && (size_t) width > length ?
        (size_t) width - length : 0;
    if (!left)
        output_repeat(output, ' ', padding);
    while (length-- != 0)
        output_char(output, *string++);
    if (left)
        output_repeat(output, ' ', padding);
}

static void output_number(struct output *output, uint64_t value,
    int negative, unsigned int base, int uppercase, int alternate,
    int plus, int space, int left, int zero, int width, int precision)
{
    char reversed[32];
    char prefix[3];
    size_t digit_count;
    size_t prefix_count = 0;
    size_t precision_zeroes;
    size_t total;
    size_t padding;

    digit_count = value == 0 && precision == 0 ? 0 :
        unsigned_digits(reversed, value, base, uppercase);
    if (negative)
        prefix[prefix_count++] = '-';
    else if (plus)
        prefix[prefix_count++] = '+';
    else if (space)
        prefix[prefix_count++] = ' ';
    if (alternate && base == 16 && value != 0) {
        prefix[prefix_count++] = '0';
        prefix[prefix_count++] = uppercase ? 'X' : 'x';
    }
    precision_zeroes = precision > 0 && (size_t) precision > digit_count ?
        (size_t) precision - digit_count : 0;
    total = prefix_count + precision_zeroes + digit_count;
    padding = width > 0 && (size_t) width > total ?
        (size_t) width - total : 0;
    if (!left && !(zero && precision < 0))
        output_repeat(output, ' ', padding);
    for (size_t index = 0; index < prefix_count; index++)
        output_char(output, prefix[index]);
    if (!left && zero && precision < 0)
        output_repeat(output, '0', padding);
    output_repeat(output, '0', precision_zeroes);
    while (digit_count-- != 0)
        output_char(output, reversed[digit_count]);
    if (left)
        output_repeat(output, ' ', padding);
}

int hisi_wpa_vsnprintf(char *buffer, size_t size, const char *format,
    va_list arguments)
{
    struct output output = { buffer, size, 0 };
    const char *cursor = format;

    if (format == NULL || (buffer == NULL && size != 0))
        return -1;
    while (*cursor != '\0') {
        int left = 0;
        int zero = 0;
        int plus = 0;
        int space = 0;
        int alternate = 0;
        int width = 0;
        int precision = -1;
        enum length_modifier length = LENGTH_DEFAULT;
        char specifier;

        if (*cursor != '%') {
            output_char(&output, *cursor++);
            continue;
        }
        cursor++;
        for (;;) {
            if (*cursor == '-') left = 1;
            else if (*cursor == '0') zero = 1;
            else if (*cursor == '+') plus = 1;
            else if (*cursor == ' ') space = 1;
            else if (*cursor == '#') alternate = 1;
            else break;
            cursor++;
        }
        if (*cursor == '*') {
            width = va_arg(arguments, int);
            if (width < 0) {
                left = 1;
                width = -width;
            }
            cursor++;
        } else {
            while (*cursor >= '0' && *cursor <= '9') {
                width = width * 10 + (*cursor - '0');
                cursor++;
            }
        }
        if (*cursor == '.') {
            cursor++;
            precision = 0;
            if (*cursor == '*') {
                precision = va_arg(arguments, int);
                if (precision < 0)
                    precision = -1;
                cursor++;
            } else {
                while (*cursor >= '0' && *cursor <= '9') {
                    precision = precision * 10 + (*cursor - '0');
                    cursor++;
                }
            }
        }
        if (*cursor == 'h') {
            cursor++;
            if (*cursor == 'h') cursor++;
        } else if (*cursor == 'l') {
            cursor++;
            length = LENGTH_LONG;
            if (*cursor == 'l') {
                cursor++;
                length = LENGTH_LONG_LONG;
            }
        } else if (*cursor == 'z') {
            cursor++;
            length = LENGTH_SIZE;
        }
        specifier = *cursor++;
        if (specifier == '%') {
            output_char(&output, '%');
        } else if (specifier == 'c') {
            char value = (char) va_arg(arguments, int);
            output_string(&output, &value, 1, width, left);
        } else if (specifier == 's') {
            const char *value = va_arg(arguments, const char *);
            size_t limit = precision >= 0 ? (size_t) precision : SIZE_MAX;
            size_t length_value;
            if (value == NULL)
                value = "(null)";
            length_value = string_length_limit(value, limit);
            output_string(&output, value, length_value, width, left);
        } else if (specifier == 'd' || specifier == 'i') {
            int64_t signed_value;
            uint64_t magnitude;
            int negative;
            if (length == LENGTH_LONG_LONG)
                signed_value = va_arg(arguments, long long);
            else if (length == LENGTH_LONG)
                signed_value = va_arg(arguments, long);
            else if (length == LENGTH_SIZE)
                signed_value = va_arg(arguments, ptrdiff_t);
            else
                signed_value = va_arg(arguments, int);
            negative = signed_value < 0;
            magnitude = negative ? (uint64_t) (-(signed_value + 1)) + 1u :
                (uint64_t) signed_value;
            output_number(&output, magnitude, negative, 10, 0, 0,
                plus, space, left, zero, width, precision);
        } else if (specifier == 'u' || specifier == 'x' ||
            specifier == 'X') {
            uint64_t value;
            unsigned int base = specifier == 'u' ? 10u : 16u;
            if (length == LENGTH_LONG_LONG)
                value = va_arg(arguments, unsigned long long);
            else if (length == LENGTH_LONG)
                value = va_arg(arguments, unsigned long);
            else if (length == LENGTH_SIZE)
                value = va_arg(arguments, size_t);
            else
                value = va_arg(arguments, unsigned int);
            output_number(&output, value, 0, base, specifier == 'X',
                alternate, plus, space, left, zero, width, precision);
        } else if (specifier == 'p') {
            uintptr_t value = (uintptr_t) va_arg(arguments, void *);
            output_number(&output, value, 0, 16, 0, 1, 0, 0,
                left, zero, width, precision);
        } else {
            output_finish(&output);
            return -1;
        }
    }
    output_finish(&output);
    return output.count > INT_MAX ? -1 : (int) output.count;
}
