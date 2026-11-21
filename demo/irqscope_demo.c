/*
 * Authored synthetic Cortex-M fixture for IRQScope.
 * The addresses and register side effects are defined by demo.svd and are not
 * a claim about any commercial MCU. Keep functions unoptimized enough for IDA
 * to retain readable instruction-level evidence.
 */
/* Keep the fixture freestanding and compiler independent. */
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

#define DEMO_UART_BASE 0x40013000u
#define UART_STATUS (*(volatile uint32_t *)(DEMO_UART_BASE + 0x00u))
#define UART_DATA   (*(volatile uint32_t *)(DEMO_UART_BASE + 0x04u))
#define UART_CONTROL (*(volatile uint32_t *)(DEMO_UART_BASE + 0x08u))
#define UART_CONFIG (*(volatile uint32_t *)(DEMO_UART_BASE + 0x0Cu))
#define UART_EVENTS (*(volatile uint32_t *)(DEMO_UART_BASE + 0x10u))
#define DEMO_NVIC_ISER_BASE 0xE000E100u
#define DEMO_NVIC_ICER_BASE 0xE000E180u
#define DEMO_NVIC_IPR_BASE  0xE000E400u
#define DEMO_NVIC_PRIORITY_BITS 3u

#define STATUS_READY (1u << 0)
#define CONTROL_START (1u << 0)

static volatile uint32_t g_last_received;
static volatile uint32_t g_irq_count;

/* Minimal named CMSIS-shaped wrappers make setup-call recovery inspectable in
 * the symbolized fixture. These touch architectural NVIC addresses only. */
__attribute__((noinline, used)) void NVIC_EnableIRQ(uint32_t irq_number)
{
    volatile uint32_t *iser = (volatile uint32_t *)DEMO_NVIC_ISER_BASE;
    iser[irq_number / 32u] = 1u << (irq_number % 32u);
}

__attribute__((noinline, used)) void NVIC_DisableIRQ(uint32_t irq_number)
{
    volatile uint32_t *icer = (volatile uint32_t *)DEMO_NVIC_ICER_BASE;
    icer[irq_number / 32u] = 1u << (irq_number % 32u);
}

__attribute__((noinline, used)) void NVIC_SetPriority(uint32_t irq_number, uint32_t priority)
{
    volatile uint8_t *ipr = (volatile uint8_t *)DEMO_NVIC_IPR_BASE;
    ipr[irq_number] = (uint8_t)(priority << (8u - DEMO_NVIC_PRIORITY_BITS));
}

static void configure_demo_interrupts(void)
{
    NVIC_DisableIRQ(1u);
    NVIC_SetPriority(0u, 2u);
    NVIC_SetPriority(1u, 3u);
    NVIC_EnableIRQ(0u);
    NVIC_EnableIRQ(1u);
}

__attribute__((noinline, used)) uint32_t transfer_unsafe(uint32_t value)
{
    while ((UART_STATUS & STATUS_READY) == 0u) {
        /* Poll until the synthetic peripheral reports ready. */
    }
    UART_DATA = value;
    UART_CONTROL = UART_CONTROL | CONTROL_START;
    while ((UART_STATUS & STATUS_READY) == 0u) {
        /* The IRQ handler can consume/clear status during this operation. */
    }
    return UART_DATA;
}

static __attribute__((always_inline)) inline uint32_t irq_save(void)
{
    uint32_t previous;
    __asm volatile("mrs %0, primask\n\tcpsid i"
                   : "=r"(previous)
                   :
                   : "memory");
    return previous;
}

static __attribute__((always_inline)) inline void irq_restore(uint32_t previous)
{
    __asm volatile("msr primask, %0" : : "r"(previous) : "memory");
}

__attribute__((noinline, used)) uint32_t transfer_masked(uint32_t value)
{
    uint32_t previous = irq_save();
    while ((UART_STATUS & STATUS_READY) == 0u) {
    }
    UART_DATA = value;
    UART_CONTROL = UART_CONTROL | CONTROL_START;
    while ((UART_STATUS & STATUS_READY) == 0u) {
    }
    uint32_t result = UART_DATA;
    irq_restore(previous);
    return result;
}

__attribute__((noinline, used)) void configure_and_acknowledge_foreground(void)
{
    /* The ordered exact writes form a compact analyst-contract example. */
    UART_CONFIG = 0x3u;
    UART_EVENTS = 0x1u;
}

__attribute__((noinline, used)) void configure_mode_byte_and_acknowledge_fixture(void)
{
    /* Byte store at CONFIG base: little-endian bits 1..2 encode MODE=FAST. */
    *(volatile uint8_t *)(DEMO_UART_BASE + 0x0Cu) = 0x2u;
    UART_EVENTS = 0x1u;
}

__attribute__((noinline, used)) void invalid_config_mode_write_fixture(void)
{
    /* MODE=3 is not listed by the synthetic SVD's enum-only write constraint. */
    UART_CONFIG = 0x7u;
}

__attribute__((naked, noinline, used)) void branch_shifted_constant_fixture(void)
{
    /* Only the CONFIG=3 store is feasible: 8 == (2 << 2), so BNE is false. */
    __asm volatile(
        "movs r0, #8\n"
        "movs r1, #2\n"
        "cmp r0, r1, lsl #2\n"
        "bne 1f\n"
        "ldr r2, =0x4001300c\n"
        "movs r3, #3\n"
        "str r3, [r2]\n"
        "b 2f\n"
        "1:\n"
        "ldr r2, =0x4001300c\n"
        "movs r3, #1\n"
        "str r3, [r2]\n"
        "2:\n"
        "bx lr\n");
}

void USART_IRQHandler(void)
{
    UART_EVENTS = 0x2u;
    uint32_t status = UART_STATUS;
    if ((status & STATUS_READY) != 0u) {
        g_last_received = UART_DATA;
        UART_CONTROL = UART_CONTROL & ~CONTROL_START;
        ++g_irq_count;
    }
}

void TIMER_IRQHandler(void)
{
    /* A second external handler helps exercise vector-table mapping. */
    UART_CONFIG = 0x1u;
    ++g_irq_count;
}

void SysTick_Handler(void)
{
    ++g_irq_count;
}

void Default_Handler(void)
{
    for (;;) {
    }
}

void main(void)
{
    configure_demo_interrupts();
    (void)transfer_unsafe(0x5Au);
    (void)transfer_masked(0xA5u);
    configure_and_acknowledge_foreground();
    configure_mode_byte_and_acknowledge_fixture();
    invalid_config_mode_write_fixture();
    for (;;) {
        __asm volatile("wfi");
    }
}

void Reset_Handler(void)
{
    main();
    for (;;) {
    }
}
