
`default_nettype none

module poly1305_top(
                input    wire       clk_i,         // clock
                input    wire       rst_i,         // reset (synchronous active high)

                input    wire       cyc_i,   
                input    wire       stb_i,         // strobe
                
                input    wire [7:0] adr_i,         // address
                input    wire       we_i,          // write enable
                input    wire[31:0] dat_i,         // data input
                input    wire[3:0]  wb_sel,        // data select
                output   wire [31:0] dat_o,         // data output
                output   reg        ack_o,         // normal bus termination
                output   wire       rty_o          // retry output      // cycle

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
  localparam ADDR_NAME0       = 8'h00;
  localparam ADDR_NAME1       = 8'h04;
  localparam ADDR_VERSION     = 8'h08;

  localparam ADDR_CTRL        = 8'h10;
  localparam CTRL_INIT_BIT    = 0;
  localparam CTRL_NEXT_BIT    = 1;
  localparam CTRL_FINISH_BIT  = 2;

  localparam ADDR_STATUS      = 8'h14;
  localparam STATUS_READY_BIT = 0;

  localparam ADDR_BLOCKLEN    = 8'h18;

  localparam ADDR_KEY0        = 8'h20;
  localparam ADDR_KEY7        = 8'h3c;

  localparam ADDR_BLOCK0      = 8'h40;
  localparam ADDR_BLOCK1      = 8'h44;
  localparam ADDR_BLOCK2      = 8'h48;
  localparam ADDR_BLOCK3      = 8'h4c;

  localparam ADDR_MAC0        = 8'h50;
  localparam ADDR_MAC1        = 8'h54;
  localparam ADDR_MAC2        = 8'h58;
  localparam ADDR_MAC3        = 8'h5c;

  localparam CORE_NAME0       = 32'h706f6c79; // "poly"
  localparam CORE_NAME1       = 32'h31333035; // "1305"
  localparam CORE_VERSION     = 32'h312e3030; // "1.00"


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg init_new;

  reg next_reg;
  reg next_new;


  reg finish_reg;
  reg finish_new;

  reg [4 : 0]   blocklen_reg;
  reg           blocklen_we;

  reg [31 : 0]  block_reg [0 : 3];
  reg           block_we;

  reg [31 : 0]  key_reg [0 : 7];
  reg           key_we;

  reg           ready_reg;

  wire [127 : 0]  mac_out;

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [31 : 0]   tmp_read_data;

  wire           core_ready;
  wire [255 : 0] core_key;
  wire [127 : 0] core_block;
  wire [127 : 0] core_mac;



  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign dat_o = tmp_read_data;

  assign core_key = {key_reg[0], key_reg[1], key_reg[2], key_reg[3],
                     key_reg[4], key_reg[5], key_reg[6], key_reg[7]};

  assign core_block = {block_reg[0], block_reg[1],
                       block_reg[2], block_reg[3]};


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  poly1305_core core(
                     .clk(clk_i),
                     .reset_n(rst_i),
                     .init(init_reg),
                     .next(next_reg),
                     .finish(finish_reg),
                     .ready(core_ready),
                     .key(core_key),
                     .block(core_block),
                     .blocklen(blocklen_reg),
                     .mac(core_mac),
                     .mac_out_mem(mac_out)
                    );


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk_i)
    begin : reg_update
      integer i;

      if (rst_i)
        begin
          for (i = 0 ; i < 4 ; i = i + 1)
            block_reg[i] <= 32'h0;

          for (i = 0 ; i < 8 ; i = i + 1)
            key_reg[i] <= 32'h0;

          blocklen_reg <= 5'h0;
          init_reg     <= 1'b0;
          next_reg     <= 1'b0;
          ready_reg    <= 1'b0;
        end
      else
        begin
          ready_reg  <= core_ready;
          init_reg   <= init_new;
          next_reg   <= next_new;
          finish_reg <= finish_new;

          if (blocklen_we)
            blocklen_reg <= dat_i[4 : 0];

          if (key_we)
            key_reg [adr_i[4 : 2]] <= dat_i;

          if (block_we)
            block_reg[adr_i[3 : 2]] <= dat_i;
        end

    end // reg_update

//always @ (posedge ready_reg)
//          out_dat_reg <= out_mac;

  //----------------------------------------------------------------
  // api
  //
  // The interface command decoding logic.
  //----------------------------------------------------------------
  //always @*
  always @(posedge clk_i)
    begin : api
      init_new      = 1'b0;
      next_new      = 1'b0;
      finish_new    = 1'b0;
      blocklen_we   = 1'b0;
      key_we        = 1'b0;
      block_we      = 1'b0;

      if (cyc_i)
        begin
          if (we_i)
            begin
              if (adr_i == ADDR_CTRL)
                begin
                  init_new   = dat_i[CTRL_INIT_BIT];
                  next_new   = dat_i[CTRL_NEXT_BIT];
                  finish_new = dat_i[CTRL_FINISH_BIT];
                end

              if (adr_i == ADDR_BLOCKLEN)
                blocklen_we = 1'h1;

              if ((adr_i >= ADDR_KEY0) && (adr_i <= ADDR_KEY7))
                key_we = 1'b1;

              if ((adr_i >= ADDR_BLOCK0) && (adr_i <= ADDR_BLOCK3))
                block_we = 1'b1;
            end // if (we)
        end //cyc
         // else
         //   begin
              /*if (adr_i == ADDR_NAME0)
                tmp_read_data = CORE_NAME0;

              if (adr_i == ADDR_NAME1)
                tmp_read_data = CORE_NAME1;

              if (adr_i == ADDR_VERSION)
                tmp_read_data = CORE_VERSION;

              if (adr_i == ADDR_STATUS)
                tmp_read_data = {31'h0, ready_reg};
              */


              //if ((adr_i >= ADDR_MAC0) && (adr_i <= ADDR_MAC3))
                //tmp_read_data = out_mac[(3 - (adr_i - ADDR_MAC0)) * 32 +: 32];
                //tmp_read_data = 32'hFFFFFFFF;
                //tmp_read_data = mac_out[(3 - (adr_i[3:2])) * 32 +: 32];
                //tmp_read_data = mac_out;

              if ((adr_i >= ADDR_KEY0) && (adr_i <= ADDR_KEY7))
                //tmp_read_data = core_key[adr_i[4 : 2]];
                tmp_read_data = key_reg[adr_i[4 : 2]];
                //tmp_read_data = 32'hEEEEEEEE;
              /////////////////////////////////////////////////
              case (adr_i)
                ADDR_MAC3:  tmp_read_data = mac_out[031 : 0 ];
                ADDR_MAC2:  tmp_read_data = mac_out[063 : 32];
                ADDR_MAC1:  tmp_read_data = mac_out[095 : 64];
                ADDR_MAC0:  tmp_read_data = mac_out[127 : 96];
                ADDR_NAME0:  tmp_read_data = CORE_NAME0;
                ADDR_NAME1:  tmp_read_data = CORE_NAME1;
                ADDR_VERSION:    tmp_read_data = CORE_VERSION;
                ADDR_STATUS: tmp_read_data = {31'h1, ready_reg};
              default:
                begin
                end
              endcase
              /////////////////////////////////////////////////

              
            end
        //end
   // end // addr_decoder
endmodule // poly1305

//======================================================================
// EOF poly1305.v
//======================================================================
