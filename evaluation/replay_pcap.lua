-- Replay a pcap file at line rate, 100 times, with software-based stats.

local mg      = require "moongen"
local device  = require "device"
local memory  = require "memory"
local log     = require "log"
local pcap    = require "pcap"

function configure(parser)
	parser:argument("dev", "Device to use."):args(1):convert(tonumber)
	parser:argument("file", "Pcap file to replay."):args(1)
	parser:option("-n --iterations", "Number of replays."):default(100):convert(tonumber)
	parser:option("-s --flush-seconds", "Seconds to wait after sending to flush TX queues."):default(5):convert(tonumber)
	local args = parser:parse()
	return args
end

function master(args)
	local dev = device.config{port = args.dev, txQueues = 1}
	device.waitForLinks()
	local queue = dev:getTxQueue(0)
	local replay = mg.startTask("replay", queue, args.file, args.iterations, args.flush_seconds)
	replay:wait()
end

function replay(queue, file, iterations, flushSeconds)
	local mempool = memory:createMemPool(4096)
	local bufs = mempool:bufArray()
	local totalPkts, totalBytes = 0, 0

	local pcapFile = pcap:newReader(file)
	local tStart = mg.getTime()
	local lastTime, lastPkts = tStart, 0

	for i = 1, iterations do
		while mg.running() do
			local n = pcapFile:read(bufs)
			if n == 0 then break end

			for j = 1, n do
				totalBytes = totalBytes + bufs[j]:getSize()
			end
			totalPkts = totalPkts + n
			queue:sendN(bufs, n)

			-- periodic software stats every second
			local now = mg.getTime()
			if now - lastTime >= 1 then
				local deltaPkts = totalPkts - lastPkts
				local deltaTime = now - lastTime
				local mpps = deltaPkts / deltaTime / 1e6
				local mbps = (totalBytes * 8) / (now - tStart) / 1e6
				log:info("[%.1fs] %.3f Mpps, %.3f Mbps", now - tStart, mpps, mbps)
				lastTime, lastPkts = now, totalPkts
			end
		end
		pcapFile:reset()
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
