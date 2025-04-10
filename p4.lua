p4_protocol = Proto("Perforce",  "Perforce Protocol")

p4_protocol.fields = {}

message_length_checksum = ProtoField.uint8("p4.length_checksum", "lengthChecksum", base.DEC)
message_length = ProtoField.uint32("p4.length", "length", base.DEC)

key_field = ProtoField.string("p4.field", "Key", base.ASCII)
value_field = ProtoField.bytes("p4.fieldValue_hex", "Value (hex)", base.COLON)
value_field_ascii = ProtoField.string("p4.fieldValue_ascii", "Value (ASCII)", base.ASCII)

p4_protocol.fields = { message_length_checksum, message_length, key_field, value_field, value_field_ascii }

function p4_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length < 5 then return end

  pinfo.cols.protocol = p4_protocol.name

  local buffer_index = 0

  local p4_tree = tree:add(p4_protocol, buffer(), "Perforce Protocol")

  local rpc_names = ""

  while buffer_index < length do
    local packet_length_checksum_val = buffer(buffer_index, 1):uint()
    local packet_length_val = buffer(buffer_index + 1, 4):le_uint()
  
    -- Validate that the message_length checksum is equal to the bytes of message_length xor'd together
    local calculated_checksum_val = 0
    for i = 0, 3 do
      local byte_val = bit.rshift(packet_length_val, i * 8)
      byte_val = bit.band(byte_val, 0xFF)
      calculated_checksum_val = bit.bxor(calculated_checksum_val, byte_val)
    end
  
    if calculated_checksum_val ~= packet_length_checksum_val then
      -- Work out how to show an error
      return
    end
  
    if packet_length_val > (length - buffer_index) then
        -- print("Packet length " .. packet_length_val .. " is greater than remaining buffer length " .. (length - 5) .. ".")

        -- we need more bytes, so set the desegment_offset to what we
        -- already consumed, and the desegment_len to how many more
        -- are needed
        pinfo.desegment_offset = buffer_index
        pinfo.desegment_len = packet_length_val - (length - buffer_index - 5)

        return length
    end

    local rpc_packet_tree = p4_tree:add(p4_protocol, buffer(buffer_index, packet_length_val + 5), "RPC Packet")
    local packet_end_index = buffer_index + packet_length_val + 5

    local header_subtree = rpc_packet_tree:add(p4_protocol, buffer(buffer_index, 5), "Header")
    header_subtree:add(message_length_checksum, packet_length_checksum_val)
    header_subtree:add_le(message_length, packet_length_val)

    buffer_index = buffer_index + 5

    -- Start printing the packet data
    local data_subtree = rpc_packet_tree:add(p4_protocol, buffer(buffer_index, packet_length_val), "Data")
  
    while buffer_index < packet_end_index do
      local current_buffer = buffer(buffer_index, -1)
  
      local key_length = current_buffer:strsize()
  
      --print("BUFFER INDEX: " .. buffer_index .. " KEY LENGTH: " .. key_length)
  
      if buffer_index + key_length > length then
        --print("BREAK1")
        break
      end
  
      local key_buf = current_buffer(0, key_length)
      local key = key_buf:stringz()
  
      --print("KEY: " .. key)
  
      buffer_index = buffer_index + key_length
  
      --print("BUFFER INDEX: " .. buffer_index .. " LENGTH: " .. length)
  
      if (buffer_index + 4) > length then
        --print("BREAK2")
        break
      end
  
      local value_length = current_buffer(key_length, 4):le_uint()
      --print("VALUE LENGTH: " .. value_length)
  
      buffer_index = buffer_index + 4
  
      if buffer_index + value_length > length then
        --print("BREAK3: " .. buffer_index .. " + " .. value_length .. " > " .. length .. " (key: " .. key .. ")")
        break
      end
  
      local value_buf = current_buffer(key_length + 4, value_length)
      --print("VALUE: " .. value)
      buffer_index = buffer_index + value_length + 1 -- +1 for the null delimiter
  
      -- Add the tree
      local kvp_buf = current_buffer(0, key_length + 4 + value_length + 1)
      
      local key_subtree = data_subtree:add(key_field, kvp_buf, key)
  
      if value_buf:len() > 0 then
        local ascii_value = value_buf:string()
        if ascii_value:len() ~= value_length then
          ascii_value = ascii_value .. " ...<TRUNCATED>..."
        end

        key_subtree:add(value_field_ascii, ascii_value)
        key_subtree:add(value_field, value_buf)

        key_subtree:append_text(" (" .. value_buf:len() .. " bytes)")
      end

      if key == "func" or key == "Func" then
        rpc_packet_tree:append_text(" (function: " .. value_buf:string() .. ")")
        
          -- Add it to our list of RPC names
        if rpc_names:len() > 0 then
          rpc_names = rpc_names .. ", " .. value_buf:string()
        else
          rpc_names = " (RPCs: " .. value_buf:string()
        end

      end
    end
  end

  if rpc_names:len() > 0 then
    rpc_names = rpc_names .. ")"
  end
  pinfo.cols.info = "P4: " .. tostring(pinfo.src_port) .. " → " .. tostring(pinfo.dst_port) .. rpc_names
  return buffer_index
end

local dissector_table_ssl = DissectorTable.get("ssl.port")
dissector_table_ssl:add(1666, p4_protocol)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1666, p4_protocol)


