`timescale 1 ns / 1 ps

module garbler_slave_lite_v0_1_S00_AXI #
(
    parameter integer C_S_AXI_DATA_WIDTH = 32,
    parameter integer C_S_AXI_ADDR_WIDTH = 5
)
(
    // Users to add ports here
    output wire [4:0]  bram_addr,
    output wire [31:0] bram_din,
    output wire [3:0]  bram_we,
    output wire        bram_en,
    // User ports ends

    // Global Clock Signal
    input wire  S_AXI_ACLK,
    // Global Reset Signal. This Signal is Active LOW
    input wire  S_AXI_ARESETN,
    // Write address
    input wire [C_S_AXI_ADDR_WIDTH-1 : 0] S_AXI_AWADDR,
    input wire [2 : 0] S_AXI_AWPROT,
    input wire  S_AXI_AWVALID,
    output wire  S_AXI_AWREADY,
    // Write data
    input wire [C_S_AXI_DATA_WIDTH-1 : 0] S_AXI_WDATA,
    input wire [(C_S_AXI_DATA_WIDTH/8)-1 : 0] S_AXI_WSTRB,
    input wire  S_AXI_WVALID,
    output wire  S_AXI_WREADY,
    // Write response
    output wire [1 : 0] S_AXI_BRESP,
    output wire  S_AXI_BVALID,
    input wire  S_AXI_BREADY,
    // Read address
    input wire [C_S_AXI_ADDR_WIDTH-1 : 0] S_AXI_ARADDR,
    input wire [2 : 0] S_AXI_ARPROT,
    input wire  S_AXI_ARVALID,
    output wire  S_AXI_ARREADY,
    // Read data
    output wire [C_S_AXI_DATA_WIDTH-1 : 0] S_AXI_RDATA,
    output wire [1 : 0] S_AXI_RRESP,
    output wire  S_AXI_RVALID,
    input wire  S_AXI_RREADY
);

    localparam integer ADDR_LSB = (C_S_AXI_DATA_WIDTH/32) + 1;
    localparam integer OPT_MEM_ADDR_BITS = 2;

    // AXI4LITE signals
    reg [C_S_AXI_ADDR_WIDTH-1 : 0] axi_awaddr;
    reg                            axi_awready;
    reg                            axi_wready;
    reg [1 : 0]                    axi_bresp;
    reg                            axi_bvalid;
    reg [C_S_AXI_ADDR_WIDTH-1 : 0] axi_araddr;
    reg                            axi_arready;
    reg [C_S_AXI_DATA_WIDTH-1 : 0] axi_rdata;
    reg [1 : 0]                    axi_rresp;
    reg                            axi_rvalid;
    reg                            aw_en;

    // Slave registers
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg0;
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg1;
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg2;
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg3;
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg4;
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg5;
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg6;
    reg [C_S_AXI_DATA_WIDTH-1:0] slv_reg7;

    integer byte_index;
    reg [C_S_AXI_DATA_WIDTH-1:0] reg_data_out;
    wire slv_reg_wren;
    wire slv_reg_rden;

    // Core/status wires
    wire         start_pulse;
    wire         generate_cmd_pulse;
    wire         reset_cmd_pulse;
    wire [127:0] seed_value;

    wire         initialized_w;
    wire         busy_w;
    wire         done_w;
    wire         success_w;
    wire         error_w;
    wire         data_valid_w;
    wire [31:0]  error_code_w;
    wire [4:0]   bram_addr_w;
    wire [31:0]  bram_din_w;
    wire [3:0]   bram_we_w;
    wire         bram_en_w;
    wire [31:0]  status_reg;

    // Sticky debug registers
    reg  [4:0]   dbg_last_addr;
    reg  [31:0]  dbg_last_din;
    reg  [3:0]   dbg_last_we;
    reg          dbg_last_en;
    wire [31:0]  dbg_info_reg;

    assign seed_value = {slv_reg7, slv_reg6, slv_reg5, slv_reg4};

    assign start_pulse        = slv_reg0[0];
    assign generate_cmd_pulse = slv_reg0[1];
    assign reset_cmd_pulse    = slv_reg0[2];

    assign status_reg[0]    = (seed_value != 128'd0); // seed valid
    assign status_reg[1]    = initialized_w;
    assign status_reg[2]    = busy_w;
    assign status_reg[3]    = done_w;
    assign status_reg[4]    = success_w;
    assign status_reg[5]    = error_w;
    assign status_reg[6]    = data_valid_w;
    assign status_reg[31:7] = 25'd0;

    assign dbg_info_reg = {22'd0, dbg_last_addr, dbg_last_we, dbg_last_en};

    assign bram_addr = bram_addr_w;
    assign bram_din  = bram_din_w;
    assign bram_we   = bram_we_w;
    assign bram_en   = bram_en_w;

    // I/O Connections assignments
    assign S_AXI_AWREADY = axi_awready;
    assign S_AXI_WREADY  = axi_wready;
    assign S_AXI_BRESP   = axi_bresp;
    assign S_AXI_BVALID  = axi_bvalid;
    assign S_AXI_ARREADY = axi_arready;
    assign S_AXI_RDATA   = axi_rdata;
    assign S_AXI_RRESP   = axi_rresp;
    assign S_AXI_RVALID  = axi_rvalid;

    // -----------------------------
    // AXI WRITE ADDRESS CHANNEL
    // -----------------------------
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            axi_awready <= 1'b0;
            aw_en       <= 1'b1;
        end else begin
            if (~axi_awready && S_AXI_AWVALID && S_AXI_WVALID && aw_en) begin
                axi_awready <= 1'b1;
                aw_en       <= 1'b0;
            end else if (S_AXI_BREADY && axi_bvalid) begin
                aw_en       <= 1'b1;
                axi_awready <= 1'b0;
            end else begin
                axi_awready <= 1'b0;
            end
        end
    end

    // Latch write address
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            axi_awaddr <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            if (~axi_awready && S_AXI_AWVALID && S_AXI_WVALID && aw_en) begin
                axi_awaddr <= S_AXI_AWADDR;
            end
        end
    end

    // -----------------------------
    // AXI WRITE DATA CHANNEL
    // -----------------------------
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            axi_wready <= 1'b0;
        end else begin
            if (~axi_wready && S_AXI_WVALID && S_AXI_AWVALID && aw_en) begin
                axi_wready <= 1'b1;
            end else begin
                axi_wready <= 1'b0;
            end
        end
    end

    assign slv_reg_wren = axi_wready && S_AXI_WVALID && axi_awready && S_AXI_AWVALID;

    // Register write logic
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            slv_reg0 <= 32'd0;
            slv_reg1 <= 32'd0;
            slv_reg2 <= 32'd0;
            slv_reg3 <= 32'd0;
            slv_reg4 <= 32'd0;
            slv_reg5 <= 32'd0;
            slv_reg6 <= 32'd0;
            slv_reg7 <= 32'd0;
        end else begin
            // pulse-only command register
            slv_reg0 <= 32'd0;

            if (slv_reg_wren) begin
                case (axi_awaddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB])
                    3'h0: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg0[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    3'h1: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg1[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    3'h2: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg2[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    3'h3: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg3[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    3'h4: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg4[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    3'h5: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg5[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    3'h6: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg6[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    3'h7: begin
                        for (byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1)
                            if (S_AXI_WSTRB[byte_index])
                                slv_reg7[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
                    end
                    default: begin
                    end
                endcase
            end
        end
    end

    // Write response channel
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            axi_bvalid <= 1'b0;
            axi_bresp  <= 2'b00;
        end else begin
            if (axi_awready && S_AXI_AWVALID && ~axi_bvalid && axi_wready && S_AXI_WVALID) begin
                axi_bvalid <= 1'b1;
                axi_bresp  <= 2'b00; // OKAY
            end else if (S_AXI_BREADY && axi_bvalid) begin
                axi_bvalid <= 1'b0;
            end
        end
    end

    // -----------------------------
    // AXI READ ADDRESS CHANNEL
    // -----------------------------
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            axi_arready <= 1'b0;
            axi_araddr  <= {C_S_AXI_ADDR_WIDTH{1'b0}};
        end else begin
            if (~axi_arready && S_AXI_ARVALID) begin
                axi_arready <= 1'b1;
                axi_araddr  <= S_AXI_ARADDR;
            end else begin
                axi_arready <= 1'b0;
            end
        end
    end

    // Read data mux
    always @(*) begin
        case (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB])
            3'h0: reg_data_out = 32'd0;
            3'h1: reg_data_out = status_reg;
            3'h2: reg_data_out = error_code_w;
            3'h3: reg_data_out = dbg_info_reg;
            3'h4: reg_data_out = slv_reg4;
            3'h5: reg_data_out = slv_reg5;
            3'h6: reg_data_out = slv_reg6;
            3'h7: reg_data_out = slv_reg7;
            default: reg_data_out = 32'd0;
        endcase
    end

    assign slv_reg_rden = axi_arready & S_AXI_ARVALID & ~axi_rvalid;

    // Read data / response
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            axi_rvalid <= 1'b0;
            axi_rresp  <= 2'b00;
            axi_rdata  <= {C_S_AXI_DATA_WIDTH{1'b0}};
        end else begin
            if (slv_reg_rden) begin
                axi_rvalid <= 1'b1;
                axi_rresp  <= 2'b00; // OKAY
                axi_rdata  <= reg_data_out;
            end else if (axi_rvalid && S_AXI_RREADY) begin
                axi_rvalid <= 1'b0;
            end
        end
    end

    // -----------------------------
    // Sticky debug capture
    // -----------------------------
    always @(posedge S_AXI_ACLK) begin
        if (!S_AXI_ARESETN) begin
            dbg_last_addr <= 5'd0;
            dbg_last_din  <= 32'd0;
            dbg_last_we   <= 4'd0;
            dbg_last_en   <= 1'b0;
        end else if (bram_en_w) begin
            dbg_last_addr <= bram_addr_w;
            dbg_last_din  <= bram_din_w;
            dbg_last_we   <= bram_we_w;
            dbg_last_en   <= bram_en_w;
        end
    end

    // -----------------------------
    // Real core instance
    // -----------------------------
    garbler_core u_garbler_core (
        .clk(S_AXI_ACLK),
        .rstn(S_AXI_ARESETN),
        .start(start_pulse),
        .generate_cmd(generate_cmd_pulse),
        .reset_cmd(reset_cmd_pulse),
        .seed(seed_value),

        .initialized(initialized_w),
        .busy(busy_w),
        .done(done_w),
        .success(success_w),
        .error(error_w),
        .data_valid(data_valid_w),
        .error_code(error_code_w),

        .bram_addr(bram_addr_w),
        .bram_din(bram_din_w),
        .bram_we(bram_we_w),
        .bram_en(bram_en_w)
    );

endmodule