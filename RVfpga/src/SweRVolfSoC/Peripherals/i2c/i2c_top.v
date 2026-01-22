`default_nettype none
//`timescale 1ns/1ps 

module i2c_top(
              input    wire       clk_i,         // clock
              input    wire       rst_i,         // reset (synchronous active high)
              input    wire       cyc_i,         // cycle
              input    wire       stb_i,         // strobe
              input    wire [7:0] adr_i,         // address
              input    wire       we_i,          // write enable
              input    wire[31:0] dat_i,         // data input
              input    wire[3:0]  wb_sel,        // data select
              output   wire [31:0] dat_o,        // data output
              output   reg        ack_o,         // normal bus termination
              output   wire       rty_o,         // retry output
              inout			wire          TMP_SDA,       //SDA
	            output		wire	        TMP_CLK        //SCL
             );

  // Wishbone interface
	wire wb_acc = cyc_i & stb_i;       // WISHBONE access
	wire wb_wr  = wb_acc & we_i;       // WISHBONE write access


	// ack_o
	always @(posedge clk_i) begin
		if (rst_i)
			ack_o <= 1'b0;
		else
			ack_o <= wb_acc & !ack_o;
	end

//rty_o
  assign rty_o = 1'b0;

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_TEMP_READING       = 8'h00;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
	wire             w_200KHz;
	wire [31:0]      w_data;
    reg [31 : 0]     tmp_read_data;
	assign dat_o  =  tmp_read_data;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------

	i2c_master master(
			.clk_200KHz(w_200KHz),
			.reset(rst_i),
			.temp_data(w_data),
			.SDA(TMP_SDA),
			.SDA_dir(),
			.SCL(TMP_CLK)
			);
			
	clkgen_200KHz cgen(
			.clk_100MHz(clk_i),
			.clk_200KHz(w_200KHz)
			);

  //----------------------------------------------------------------
  // Address decoder logic.
  //----------------------------------------------------------------
  //always @*
  always @(posedge clk_i)
    begin : addr_decoder
      tmp_read_data = 32'h0;

      if (cyc_i)
        begin
          if (we_i)
            begin
              case (adr_i)
                ADDR_TEMP_READING:   tmp_read_data = w_data;

                default:
                  begin
                  end
              endcase // case (address)
            end
        end
    end

endmodule