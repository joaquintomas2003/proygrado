-- Replay a pcap file at line rate (100 times), computing PPS and Mbps

local mg      = require "moongen"
local device  = require "device"
local memory  = require "memory"
local stats   = require "stats"
local log     = require "log"
local pcap    = require "pcap"

function configure(parser)
	parser:argument("dev", "Device to use."):args(1):convert(tonumber)
	parser:argument("file", "Pcap file to replay."):args(1)
	parser:option("-n --iterations", "Number of times to replay the file."):default(100):convert(tonumber)
	parser:option("-s --sleep-time", "Seconds to wait for TX queues to flush."):default(5):convert(tonumber)
	local args = parser:parse()
	return args
end

function master(args)
	local dev = device.config{port = args.dev, txQueues = 1}
	device.waitForLinks()
	local queue = dev:getTxQueue(0)
	stats.startStatsTask{txDevices = {dev}}
	local task = mg.startTask("replay", queue, args.file, args.iterations, args.sleep_time)
	task:wait()
end

function replay(queue, file, iterations, sleepTime)
	local mempool = memory:createMemPool(4096)
	local bufs = mempool:bufArray()
	local totalPkts = 0
	local totalBytes = 0

	local pcapFile = pcap:newReader(file)

	local t0 = mg.getTime()

	for i = 1, iterations do
		while mg.running() do
			local n = pcapFile:read(bufs)
			if n == 0 then
				break
			end

			-- Sum total bytes for Mbps computation
			for j = 1, n do
				totalBytes = totalBytes + bufs[j]:getSize()
			end
			totalPkts = totalPkts + n

			queue:sendN(bufs, n)
		end

		pcapFile:reset()
	end

	local t1 = mg.getTime()
	local elapsed = t1 - t0
	local pps = totalPkts / elapsed
	local mbps = (totalBytes * 8) / elapsed / 1e6

	log:info("Replayed %d packets in %.3f seconds", totalPkts, elapsed)
	log:info("Average rate: %.3f Mpps (%.3f Mbps)", pps / 1e6, mbps)
	log:info("Waiting %.1f seconds to flush TX queues...", sleepTime)
	mg.sleepMillisIdle(sleepTime * 1000)
end
