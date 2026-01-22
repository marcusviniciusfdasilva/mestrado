//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 24.04.2023 16:23:46
// Design Name: 
// Module Name: XADC
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////
`timescale 1ns/1ps

module xadc_top(
    input wire        wb_clk_i,     //check
    input wire        wb_rst_i,     //check
    input wire        wb_cyc_i,     //check
    input wire [7:0]  wb_adr_i,     //endereço de entrada
    input wire [31:0] wb_dat_i,     //dados de entrada 
    input wire        wb_sel_i,     //check
    input wire        wb_we_i,      //check
    input wire        wb_stb_i,     //check
    output wire [31:0] wb_dat_o,     //dados de saida
    output reg        wb_ack_o,     //check
    output wire       wb_err_o,    //check

    //external
    input vauxn3,
    input vauxp3,
    input vauxn10,
    input vauxp10,
    input vauxn2,
    input vauxp2,
    input vauxn11,
    input vauxp11,
    input vp_in,
    input vn_in);

    localparam ADDR_ADR       = 8'h80;
    localparam ADDR_DATA      = 8'h84;
    localparam ADDR_STATUS    = 8'h88;
    localparam ADDR_CRTL      = 8'h8c;
    localparam ADDR_TESTE     = 8'h90;
    localparam ADDR_RW        = 8'h94;

  reg teste;
  reg [3:0] test = 4'b0010;

  reg [31:0] address_in;

  reg [15:0] data;
  wire [15:0] datakeep;

  reg [15:0] data_in;

  wire enable;
  wire ready;

  reg [7:0] STATUS;
  reg [31:0] stat;
  reg [31:0] CRTL;
  reg [31:0] CORTL;

  reg conv = 0;
  wire conv_in;
  assign conv_in = conv;
 
  wire stat_out;
  assign stat_out = stat;
 
  reg [31:0] data_out;
  assign wb_dat_o = data_out;
 
  reg [1:0]rw;
  reg [1:0] den;
  reg [1:0] dwe;
 
  wire busy;

  xadc_wiz_0 XLXI_7 (
    .convst_in(conv_in), // Convert Start Input
    .daddr_in(address_in), //DRP // Address bus for the dynamic reconfiguration port
    .dclk_in(wb_clk_i), //DRP // Clock input for the dynamic reconfiguration port
    .den_in(den[0]), //DRP // Enable Signal for the dynamic reconfiguration port
    .di_in(data_in), //DRP // Input data bus for the dynamic reconfiguration port
    .dwe_in(dwe[0]), //DRP // Write Enable for the dynamic reconfiguration port
    .reset_in(0), // Reset signal for the System Monitor control logic
    .vauxp2(vauxp2), // Auxiliary channel 2
    .vauxn2(vauxn2),
    .vauxp3(vauxp3), // Auxiliary channel 3
    .vauxn3(vauxn3),
    .vauxp10(vauxp10), // Auxiliary channel 10
    .vauxn10(vauxn10),
    .vauxp11(vauxp11), // Auxiliary channel 11
    .vauxn11(vauxn11),
    .busy_out(busy), // ADC Busy signal
    .channel_out(), // Channel Selection Outputs
    .do_out(datakeep), //DRP // Output data bus for dynamic reconfiguration port
    .drdy_out(ready), //DRP // Data ready signal for the dynamic reconfiguration port
    .eoc_out(enable), // End of Conversion Signal
    .eos_out(), // End of Sequence Signal
    .vccaux_alarm_out(), // VCCAUX-sensor alarm output
    .vccint_alarm_out(), // VCCINT-sensor alarm output
    .alarm_out(), // OR'ed output of all the Alarms 
    .vp_in(vp_in), // Dedicated Analog Input Pair
    .vn_in(vn_in));

//implementaion
//Wishbone interface

wire wb_acc = wb_cyc_i & wb_stb_i; // WISHBONE access
wire wb_wr = wb_acc & wb_we_i; // WISHBONE write access

// ack_o

always @(posedge wb_clk_i) begin
if (wb_rst_i)
wb_ack_o <= 1'b0;
else
wb_ack_o <= wb_acc & !wb_ack_o;
end

 //dat_in

 always @(posedge wb_clk_i)begin:ola
 data_out = 32'h0;
 if (wb_rst_i)
 begin
 address_in <= 32'h0; // set master bit

 //data = 32'h0;
 
 STATUS = 32'h0;
 end
 else if (wb_wr)
 begin
 if (wb_adr_i == ADDR_ADR)
 address_in <= wb_dat_i; // always set master bit
 
 if (wb_adr_i == ADDR_DATA)
 data_in <= wb_dat_i;
 if (wb_adr_i == ADDR_CRTL)
 CRTL <= wb_dat_i;
 if (wb_adr_i == ADDR_STATUS)
 STATUS <= wb_dat_i;
 
 if (wb_adr_i == ADDR_TESTE)
 teste <= wb_dat_i;
 
 if (wb_adr_i == ADDR_RW)
 rw = wb_dat_i;
 end

 // dat_o

 case(wb_adr_i) // synopsys full_case parallel_case
 ADDR_ADR: data_out = address_in;
 ADDR_DATA: data_out = data;
 ADDR_STATUS: data_out = stat;
 ADDR_CRTL: data_out = CORTL;
 ADDR_TESTE: data_out = test;
 default: data_out = 1234;
 endcase
 end
 
 //Logic
 
 always @(posedge wb_clk_i) begin 
 if(CRTL == 1'h1)begin
 conv = 1'h1;
 if(enable != 0)begin
 conv = 1'h0;
 CORTL = 1'h0;
 stat = 1'h1;
 end
 end 
 end 
 always @(posedge wb_clk_i) begin
 if(ready == 1) begin
 data <= datakeep;
 end
 end
 always@(posedge wb_clk_i) begin
 case(rw)
 2'b00: begin
 den[0] <= 0;
 dwe[0] <= 0;
 end
 2'b01: begin
 if(busy == 0) begin
 den <= 2'h2;
 end
 
 else begin
 den <= { 1'b0, den[1] };
 end 
 end
 2'b10: begin
 if(busy == 0) begin
 den <= 2'h2;
 dwe <= 2'h2;
 end
 else begin
 den <= {1'b0, den[1]};
 dwe <= {1'b0, dwe[1]};
 end 
 end
 endcase 
 end
 
endmodule