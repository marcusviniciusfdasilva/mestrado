wire [31:0] wb_m2s_io_adr;
wire [31:0] wb_m2s_io_dat;
wire  [3:0] wb_m2s_io_sel;
wire        wb_m2s_io_we;
wire        wb_m2s_io_cyc;
wire        wb_m2s_io_stb;
wire  [2:0] wb_m2s_io_cti;
wire  [1:0] wb_m2s_io_bte;
wire [31:0] wb_s2m_io_dat;
wire        wb_s2m_io_ack;
wire        wb_s2m_io_err;
wire        wb_s2m_io_rty;
wire [31:0] wb_m2s_rom_adr;
wire [31:0] wb_m2s_rom_dat;
wire  [3:0] wb_m2s_rom_sel;
wire        wb_m2s_rom_we;
wire        wb_m2s_rom_cyc;
wire        wb_m2s_rom_stb;
wire  [2:0] wb_m2s_rom_cti;
wire  [1:0] wb_m2s_rom_bte;
wire [31:0] wb_s2m_rom_dat;
wire        wb_s2m_rom_ack;
wire        wb_s2m_rom_err;
wire        wb_s2m_rom_rty;
wire [31:0] wb_m2s_spi_flash_adr;
wire [31:0] wb_m2s_spi_flash_dat;
wire  [3:0] wb_m2s_spi_flash_sel;
wire        wb_m2s_spi_flash_we;
wire        wb_m2s_spi_flash_cyc;
wire        wb_m2s_spi_flash_stb;
wire  [2:0] wb_m2s_spi_flash_cti;
wire  [1:0] wb_m2s_spi_flash_bte;
wire [31:0] wb_s2m_spi_flash_dat;
wire        wb_s2m_spi_flash_ack;
wire        wb_s2m_spi_flash_err;
wire        wb_s2m_spi_flash_rty;
wire [31:0] wb_m2s_sys_adr;
wire [31:0] wb_m2s_sys_dat;
wire  [3:0] wb_m2s_sys_sel;
wire        wb_m2s_sys_we;
wire        wb_m2s_sys_cyc;
wire        wb_m2s_sys_stb;
wire  [2:0] wb_m2s_sys_cti;
wire  [1:0] wb_m2s_sys_bte;
wire [31:0] wb_s2m_sys_dat;
wire        wb_s2m_sys_ack;
wire        wb_s2m_sys_err;
wire        wb_s2m_sys_rty;
wire [31:0] wb_m2s_uart_adr;
wire [31:0] wb_m2s_uart_dat;
wire  [3:0] wb_m2s_uart_sel;
wire        wb_m2s_uart_we;
wire        wb_m2s_uart_cyc;
wire        wb_m2s_uart_stb;
wire  [2:0] wb_m2s_uart_cti;
wire  [1:0] wb_m2s_uart_bte;
wire [31:0] wb_s2m_uart_dat;
wire        wb_s2m_uart_ack;
wire        wb_s2m_uart_err;
wire        wb_s2m_uart_rty;

// GPIO
wire [31:0] wb_m2s_gpio_adr;
wire [31:0] wb_m2s_gpio_dat;
wire  [3:0] wb_m2s_gpio_sel;
wire        wb_m2s_gpio_we;
wire        wb_m2s_gpio_cyc;
wire        wb_m2s_gpio_stb;
wire  [2:0] wb_m2s_gpio_cti;
wire  [1:0] wb_m2s_gpio_bte;
wire [31:0] wb_s2m_gpio_dat;
wire        wb_s2m_gpio_ack;
wire        wb_s2m_gpio_err;
wire        wb_s2m_gpio_rty;

// PTC
wire [31:0] wb_m2s_ptc_adr;
wire [31:0] wb_m2s_ptc_dat;
wire  [3:0] wb_m2s_ptc_sel;
wire        wb_m2s_ptc_we;
wire        wb_m2s_ptc_cyc;
wire        wb_m2s_ptc_stb;
wire  [2:0] wb_m2s_ptc_cti;
wire  [1:0] wb_m2s_ptc_bte;
wire [31:0] wb_s2m_ptc_dat;
wire        wb_s2m_ptc_ack;
wire        wb_s2m_ptc_err;
wire        wb_s2m_ptc_rty;

// SPI
wire [31:0] wb_m2s_spi_accel_adr;
wire [31:0] wb_m2s_spi_accel_dat;
wire  [3:0] wb_m2s_spi_accel_sel;
wire        wb_m2s_spi_accel_we;
wire        wb_m2s_spi_accel_cyc;
wire        wb_m2s_spi_accel_stb;
wire  [2:0] wb_m2s_spi_accel_cti;
wire  [1:0] wb_m2s_spi_accel_bte;
wire [31:0] wb_s2m_spi_accel_dat;
wire        wb_s2m_spi_accel_ack;
wire        wb_s2m_spi_accel_err;
wire        wb_s2m_spi_accel_rty;

// I2C
wire [31:0] wb_m2s_i2c_adr;
wire [31:0] wb_m2s_i2c_dat;
wire  [3:0] wb_m2s_i2c_sel;
wire        wb_m2s_i2c_we;
wire        wb_m2s_i2c_cyc;
wire        wb_m2s_i2c_stb;
wire  [2:0] wb_m2s_i2c_cti;
wire  [1:0] wb_m2s_i2c_bte;
wire [31:0] wb_s2m_i2c_dat;
wire        wb_s2m_i2c_ack;
wire        wb_s2m_i2c_err;
wire        wb_s2m_i2c_rty;

// CHACHA20
wire [31:0] wb_m2s_chacha_adr;
wire [31:0] wb_m2s_chacha_dat;
wire  [3:0] wb_m2s_chacha_sel;
wire        wb_m2s_chacha_we;
wire        wb_m2s_chacha_cyc;
wire        wb_m2s_chacha_stb;
wire  [2:0] wb_m2s_chacha_cti;
wire  [1:0] wb_m2s_chacha_bte;
wire [31:0] wb_s2m_chacha_dat;
wire        wb_s2m_chacha_ack;
wire        wb_s2m_chacha_err;
wire        wb_s2m_chacha_rty;

// POLY1305
wire [31:0] wb_m2s_poly1305_adr;
wire [31:0] wb_m2s_poly1305_dat;
wire  [3:0] wb_m2s_poly1305_sel;
wire        wb_m2s_poly1305_we;
wire        wb_m2s_poly1305_cyc;
wire        wb_m2s_poly1305_stb;
wire  [2:0] wb_m2s_poly1305_cti;
wire  [1:0] wb_m2s_poly1305_bte;
wire [31:0] wb_s2m_poly1305_dat;
wire        wb_s2m_poly1305_ack;
wire        wb_s2m_poly1305_err;
wire        wb_s2m_poly1305_rty;

// ADC
wire [31:0] wb_m2s_adc_adr;
wire [31:0] wb_m2s_adc_dat;
wire  [3:0] wb_m2s_adc_sel;
wire        wb_m2s_adc_we;
wire        wb_m2s_adc_cyc;
wire        wb_m2s_adc_stb;
wire  [2:0] wb_m2s_adc_cti;
wire  [1:0] wb_m2s_adc_bte;
wire [31:0] wb_s2m_adc_dat;
wire        wb_s2m_adc_ack;
wire        wb_s2m_adc_err;
wire        wb_s2m_adc_rty;

wb_intercon wb_intercon0
   (.wb_clk_i           (wb_clk),
    .wb_rst_i           (wb_rst),
    .wb_io_adr_i        (wb_m2s_io_adr),
    .wb_io_dat_i        (wb_m2s_io_dat),
    .wb_io_sel_i        (wb_m2s_io_sel),
    .wb_io_we_i         (wb_m2s_io_we),
    .wb_io_cyc_i        (wb_m2s_io_cyc),
    .wb_io_stb_i        (wb_m2s_io_stb),
    .wb_io_cti_i        (wb_m2s_io_cti),
    .wb_io_bte_i        (wb_m2s_io_bte),
    .wb_io_dat_o        (wb_s2m_io_dat),
    .wb_io_ack_o        (wb_s2m_io_ack),
    .wb_io_err_o        (wb_s2m_io_err),
    .wb_io_rty_o        (wb_s2m_io_rty),
    .wb_rom_adr_o       (wb_m2s_rom_adr),
    .wb_rom_dat_o       (wb_m2s_rom_dat),
    .wb_rom_sel_o       (wb_m2s_rom_sel),
    .wb_rom_we_o        (wb_m2s_rom_we),
    .wb_rom_cyc_o       (wb_m2s_rom_cyc),
    .wb_rom_stb_o       (wb_m2s_rom_stb),
    .wb_rom_cti_o       (wb_m2s_rom_cti),
    .wb_rom_bte_o       (wb_m2s_rom_bte),
    .wb_rom_dat_i       (wb_s2m_rom_dat),
    .wb_rom_ack_i       (wb_s2m_rom_ack),
    .wb_rom_err_i       (wb_s2m_rom_err),
    .wb_rom_rty_i       (wb_s2m_rom_rty),
    .wb_spi_flash_adr_o (wb_m2s_spi_flash_adr),
    .wb_spi_flash_dat_o (wb_m2s_spi_flash_dat),
    .wb_spi_flash_sel_o (wb_m2s_spi_flash_sel),
    .wb_spi_flash_we_o  (wb_m2s_spi_flash_we),
    .wb_spi_flash_cyc_o (wb_m2s_spi_flash_cyc),
    .wb_spi_flash_stb_o (wb_m2s_spi_flash_stb),
    .wb_spi_flash_cti_o (wb_m2s_spi_flash_cti),
    .wb_spi_flash_bte_o (wb_m2s_spi_flash_bte),
    .wb_spi_flash_dat_i (wb_s2m_spi_flash_dat),
    .wb_spi_flash_ack_i (wb_s2m_spi_flash_ack),
    .wb_spi_flash_err_i (wb_s2m_spi_flash_err),
    .wb_spi_flash_rty_i (wb_s2m_spi_flash_rty),
    .wb_sys_adr_o       (wb_m2s_sys_adr),
    .wb_sys_dat_o       (wb_m2s_sys_dat),
    .wb_sys_sel_o       (wb_m2s_sys_sel),
    .wb_sys_we_o        (wb_m2s_sys_we),
    .wb_sys_cyc_o       (wb_m2s_sys_cyc),
    .wb_sys_stb_o       (wb_m2s_sys_stb),
    .wb_sys_cti_o       (wb_m2s_sys_cti),
    .wb_sys_bte_o       (wb_m2s_sys_bte),
    .wb_sys_dat_i       (wb_s2m_sys_dat),
    .wb_sys_ack_i       (wb_s2m_sys_ack),
    .wb_sys_err_i       (wb_s2m_sys_err),
    .wb_sys_rty_i       (wb_s2m_sys_rty),
    .wb_uart_adr_o      (wb_m2s_uart_adr),
    .wb_uart_dat_o      (wb_m2s_uart_dat),
    .wb_uart_sel_o      (wb_m2s_uart_sel),
    .wb_uart_we_o       (wb_m2s_uart_we),
    .wb_uart_cyc_o      (wb_m2s_uart_cyc),
    .wb_uart_stb_o      (wb_m2s_uart_stb),
    .wb_uart_cti_o      (wb_m2s_uart_cti),
    .wb_uart_bte_o      (wb_m2s_uart_bte),
    .wb_uart_dat_i      (wb_s2m_uart_dat),
    .wb_uart_ack_i      (wb_s2m_uart_ack),
    .wb_uart_err_i      (wb_s2m_uart_err),
    .wb_uart_rty_i      (wb_s2m_uart_rty),
// GPIO
    .wb_gpio_adr_o      (wb_m2s_gpio_adr),
    .wb_gpio_dat_o      (wb_m2s_gpio_dat),
    .wb_gpio_sel_o      (wb_m2s_gpio_sel),
    .wb_gpio_we_o       (wb_m2s_gpio_we),
    .wb_gpio_cyc_o      (wb_m2s_gpio_cyc),
    .wb_gpio_stb_o      (wb_m2s_gpio_stb),
    .wb_gpio_cti_o      (wb_m2s_gpio_cti),
    .wb_gpio_bte_o      (wb_m2s_gpio_bte),
    .wb_gpio_dat_i      (wb_s2m_gpio_dat),
    .wb_gpio_ack_i      (wb_s2m_gpio_ack),
    .wb_gpio_err_i      (wb_s2m_gpio_err),
    .wb_gpio_rty_i      (wb_s2m_gpio_rty),
// PTC
    .wb_ptc_adr_o      (wb_m2s_ptc_adr),
    .wb_ptc_dat_o      (wb_m2s_ptc_dat),
    .wb_ptc_sel_o      (wb_m2s_ptc_sel),
    .wb_ptc_we_o       (wb_m2s_ptc_we),
    .wb_ptc_cyc_o      (wb_m2s_ptc_cyc),
    .wb_ptc_stb_o      (wb_m2s_ptc_stb),
    .wb_ptc_cti_o      (wb_m2s_ptc_cti),
    .wb_ptc_bte_o      (wb_m2s_ptc_bte),
    .wb_ptc_dat_i      (wb_s2m_ptc_dat),
    .wb_ptc_ack_i      (wb_s2m_ptc_ack),
    .wb_ptc_err_i      (wb_s2m_ptc_err),
    .wb_ptc_rty_i      (wb_s2m_ptc_rty),
// SPI
    .wb_spi_accel_adr_o (wb_m2s_spi_accel_adr),
    .wb_spi_accel_dat_o (wb_m2s_spi_accel_dat),
    .wb_spi_accel_sel_o (wb_m2s_spi_accel_sel),
    .wb_spi_accel_we_o  (wb_m2s_spi_accel_we),
    .wb_spi_accel_cyc_o (wb_m2s_spi_accel_cyc),
    .wb_spi_accel_stb_o (wb_m2s_spi_accel_stb),
    .wb_spi_accel_cti_o (wb_m2s_spi_accel_cti),
    .wb_spi_accel_bte_o (wb_m2s_spi_accel_bte),
    .wb_spi_accel_dat_i (wb_s2m_spi_accel_dat),
    .wb_spi_accel_ack_i (wb_s2m_spi_accel_ack),
    .wb_spi_accel_err_i (wb_s2m_spi_accel_err),
    .wb_spi_accel_rty_i (wb_s2m_spi_accel_rty),

// i2c
    .wb_i2c_adr_o (wb_m2s_i2c_adr),
    .wb_i2c_dat_o (wb_m2s_i2c_dat),
    .wb_i2c_sel_o (wb_m2s_i2c_sel),
    .wb_i2c_we_o  (wb_m2s_i2c_we),
    .wb_i2c_cyc_o (wb_m2s_i2c_cyc),
    .wb_i2c_stb_o (wb_m2s_i2c_stb),
    .wb_i2c_cti_o (wb_m2s_i2c_cti),
    .wb_i2c_bte_o (wb_m2s_i2c_bte),
    .wb_i2c_dat_i (wb_s2m_i2c_dat),
    .wb_i2c_ack_i (wb_s2m_i2c_ack),
    .wb_i2c_err_i (wb_s2m_i2c_err),
    .wb_i2c_rty_i (wb_s2m_i2c_rty),

// CHACHA20
    .wb_chacha_adr_o (wb_m2s_chacha_adr),
    .wb_chacha_dat_o (wb_m2s_chacha_dat),
    .wb_chacha_sel_o (wb_m2s_chacha_sel),
    .wb_chacha_we_o  (wb_m2s_chacha_we),
    .wb_chacha_cyc_o (wb_m2s_chacha_cyc),
    .wb_chacha_stb_o (wb_m2s_chacha_stb),
    .wb_chacha_cti_o (wb_m2s_chacha_cti),
    .wb_chacha_bte_o (wb_m2s_chacha_bte),
    .wb_chacha_dat_i (wb_s2m_chacha_dat),
    .wb_chacha_ack_i (wb_s2m_chacha_ack),
    .wb_chacha_err_i (wb_s2m_chacha_err),
    .wb_chacha_rty_i (wb_s2m_chacha_rty),

// POLY1305
    .wb_poly1305_adr_o (wb_m2s_poly1305_adr),
    .wb_poly1305_dat_o (wb_m2s_poly1305_dat),
    .wb_poly1305_sel_o (wb_m2s_poly1305_sel),
    .wb_poly1305_we_o  (wb_m2s_poly1305_we),
    .wb_poly1305_cyc_o (wb_m2s_poly1305_cyc),
    .wb_poly1305_stb_o (wb_m2s_poly1305_stb),
    .wb_poly1305_cti_o (wb_m2s_poly1305_cti),
    .wb_poly1305_bte_o (wb_m2s_poly1305_bte),
    .wb_poly1305_dat_i (wb_s2m_poly1305_dat),
    .wb_poly1305_ack_i (wb_s2m_poly1305_ack),
    .wb_poly1305_err_i (wb_s2m_poly1305_err),
    .wb_poly1305_rty_i (wb_s2m_poly1305_rty),

// ADC
    .wb_adc_adr_o      (wb_m2s_adc_adr),
    .wb_adc_dat_o      (wb_m2s_adc_dat),
    .wb_adc_sel_o      (wb_m2s_adc_sel),
    .wb_adc_we_o       (wb_m2s_adc_we),
    .wb_adc_cyc_o      (wb_m2s_adc_cyc),
    .wb_adc_stb_o      (wb_m2s_adc_stb),
    .wb_adc_cti_o      (wb_m2s_adc_cti),
    .wb_adc_bte_o      (wb_m2s_adc_bte),
    .wb_adc_dat_i      (wb_s2m_adc_dat),
    .wb_adc_ack_i      (wb_s2m_adc_ack),
    .wb_adc_err_i      (wb_s2m_adc_err),
    .wb_adc_rty_i      (wb_s2m_adc_rty));