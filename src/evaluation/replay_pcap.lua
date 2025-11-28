-- Replay a pcap file at line rate, 100 times, with software-based stats.

local mg      = require "moongen"
local device  = require "device"
local memory  = require "memory"
local log     = require "log"
local pcap    = require "pcap"

function configure(parser)
  parser:argument("dev", "Device to use."):args(1):convert(tonumber)
  parser:argument("file", "Pcap file to replay."):args(1)
  parser:option("-n --iterations", "Number of replays."):default(10):convert(tonumber)
  parser:option("-s --flush-seconds", "Seconds to wait after sending to flush TX queues."):default(5):convert(tonumber)
  local args = parser:parse()
  return args
end

function master(args)
  local dev = device.config{port = args.dev, txQueues = 1}
  device.waitForLinks()
  local queue = dev:getTxQueue(0)
  local RATE = 10000   -- 10 Gbps
  local replay = mg.startTask("replay", queue, args.file, args.iterations, args.flush_seconds, RATE)
  replay:wait()
end

function replay(queue, file, iterations, flushSeconds, rateMbps)
  local mempool = memory:createMemPool()
  local bufs = mempool:bufArray()

  local pcapFile = pcap:newReader(file)

  local totalPkts, totalBytes = 0, 0
  local tStart = mg.getTime()
  local lastTime, lastPkts = tStart, 0

  -- rate control state
  local rate_bps = rateMbps * 1e6         -- convert Mbps → bit/s
  local nextSend = tStart

  for i = 1, iterations do
    pcapFile:reset()
    while mg.running() do
      local n = pcapFile:read(bufs)
      if n == 0 then break end

      -- compute total bytes in this batch
      local batchBytes = 0
      for j = 1, n do
        local sz = bufs[j]:getSize()
        batchBytes = batchBytes + sz
        totalBytes = totalBytes + sz
      end

      totalPkts = totalPkts + n

      -- Time the batch SHOULD take on the wire
      local batchBits = batchBytes * 8
      local batchTime = batchBits / rate_bps   -- seconds

      -- schedule next send time
      nextSend = nextSend + batchTime

      -- enforce pacing until nextSend
      local now = mg.getTime()
      local sleep = nextSend - now
      if sleep > 0 then
        mg.sleepMicrosIdle(sleep * 1e6)      -- convert to microseconds
      end
      --------------------------------------------------------------------

      queue:sendN(bufs, n)

      -- periodic stats
      local now2 = mg.getTime()
      if now2 - lastTime >= 1 then
        local deltaPkts = totalPkts - lastPkts
        local deltaTime = now2 - lastTime
        local mpps = deltaPkts / deltaTime / 1e6
        local mbps = (totalBytes * 8) / (now2 - tStart) / 1e6
        log:info("[%.1fs] %.3f Mpps, %.3f Mbps",
          now2 - tStart, mpps, mbps)
        lastTime = now2
        lastPkts = totalPkts
      end
    end
  end

  local elapsed = mg.getTime() - tStart
  local mpps = totalPkts / elapsed / 1e6
  local mbps = (totalBytes * 8) / elapsed / 1e6

  log:info("======================================")
  log:info("Finished %d replays of %s", iterations, file)
  log:info("Total: %.0f packets in %.3f s", totalPkts, elapsed)
  log:info("Average rate: %.3f Mpps, %.3f Mbps", mpps, mbps)
  log:info("======================================")

  mg.sleepMillisIdle(flushSeconds * 1000)
end
