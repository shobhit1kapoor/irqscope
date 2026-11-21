.syntax unified
.cpu cortex-m4
.thumb

.section .isr_vector,"a",%progbits
.global __vector_table
__vector_table:
    .word __stack_top
    .word Reset_Handler
    .word Default_Handler       /* NMI */
    .word Default_Handler       /* HardFault */
    .word Default_Handler       /* MemManage */
    .word Default_Handler       /* BusFault */
    .word Default_Handler       /* UsageFault */
    .word 0
    .word 0
    .word 0
    .word 0
    .word Default_Handler       /* SVCall */
    .word Default_Handler       /* Debug monitor */
    .word 0
    .word Default_Handler       /* PendSV */
    .word SysTick_Handler       /* SysTick */
    .word USART_IRQHandler      /* External IRQ 0 */
    .word TIMER_IRQHandler      /* External IRQ 1 */

