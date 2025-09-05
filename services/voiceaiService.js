// services/voiceaiService.js
const axios = require("axios");
// Smart limit configuration based on time period
const LIMIT_CONFIG = {
  "1":100,    // 1 day - very fast
  "7": 500,    // 7 days - usually fast
  "30": 700,   // 30 days - reasonable performance
  "60": 1000,   // 60 days - moderate performance
  "all": 1000,  // All time - will use pagination
};

const createKnowledgeBase = async (payload) => {
  try {
    const response = await axios.post(
      "https://api.vapi.ai/knowledge-base",
      payload,
      {
        headers: {
          Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    return response.data;
  } catch (error) {
    console.error("Vapi createKnowledgeBase error:", error.response?.data || error.message);
    throw new Error("Failed to create knowledge base");
  }
};
// Calculate date range based on days
const calculateDateRange = (days) => {
  const endDate = new Date();
  let startDate;

  if (days === "all") {
    // For "all time", go back 2 years (should cover most use cases)
    startDate = new Date();
    startDate.setFullYear(startDate.getFullYear() - 2);
  } else {
    startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
  }

  return {
    startDate: startDate.toISOString(),
    endDate: endDate.toISOString(),
  };
};

// Smart call fetching with optimized limits
const fetchCallsOptimized = async (params) => {
  const {
    assistantId,
    days,
    customStartDate,
    customEndDate,
    earliestAt, // 🆕
    latestAt,   // 🆕
    phoneNumberId, // 🆕 Added phoneNumberId param
  } = params;

  try {
    // Determine date range
    let startDate, endDate;
    if (customStartDate && customEndDate) {
      startDate = customStartDate;
      endDate = customEndDate;
    } else {
      const dateRange = calculateDateRange(days || "7");
      startDate = dateRange.startDate;
      endDate = dateRange.endDate;
    }
    console.log(`Fetching calls from ${startDate} to ${endDate}`);
    console.log(days)

    const limit = LIMIT_CONFIG[days] || LIMIT_CONFIG["30"];
    console.log(`Using limit: ${limit}`);
    const queryParams = new URLSearchParams();
    if (assistantId) queryParams.append("assistantId", assistantId);
    if (phoneNumberId) queryParams.append("phoneNumberId", phoneNumberId); // <-- Added here
    queryParams.append("createdAtGt", startDate);
    queryParams.append("createdAtLt", endDate);
    queryParams.append("limit", limit.toString());

    // 🆕 Add scheduled time filters
    if (earliestAt) queryParams.append("earliestAt", earliestAt);
    if (latestAt) queryParams.append("latestAt", latestAt);

    const url = `https://api.vapi.ai/call?${queryParams.toString()}`;

    console.log(`Fetching calls with optimized limit ${limit} for ${days} days`);

    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.VAPI_API_KEY}`,
        "Content-Type": "application/json",
      },
    });

    const calls = response.data;
    const chartData = processCallsForCharts(calls, days);
    console.log(`Fetched ${calls.length} calls`);

    return {
      calls,
      chartData,
      totalCalls: calls.length,
      dateRange: { startDate, endDate },
      limit,
    };
  } catch (error) {
    console.error("Vapi fetchCallsOptimized error:", error.response?.data || error.message);
    throw new Error("Failed to fetch optimized calls data");
  }
};



// Process calls data for chart consumption
const processCallsForCharts = (calls, timePeriod) => {
  if (!calls || calls.length === 0) {
    return {
      dailyCounts: [],
      totalCalls: 0,
      successfulCalls: 0,
      avgDuration: 0,
      endReasons: {},
    };
  }

  // Daily call counts
  const dailyCounts = {};
  let totalDuration = 0;
  let successfulCalls = 0;
  const endReasons = {};

  calls.forEach(call => {
    const date = new Date(call.createdAt).toISOString().split('T')[0];
    dailyCounts[date] = (dailyCounts[date] || 0) + 1;

    // Calculate duration
    if (call.startedAt && call.endedAt) {
      const duration = new Date(call.endedAt) - new Date(call.startedAt);
      totalDuration += duration;
    }

    // Success evaluation
    if (call.analysis?.successEvaluation === "success" || call.status === "completed") {
      successfulCalls++;
    }

    // End reasons
    if (call.endedReason) {
      endReasons[call.endedReason] = (endReasons[call.endedReason] || 0) + 1;
    }
  });

  const avgDuration = calls.length > 0 ? totalDuration / calls.length : 0;

  return {
    dailyCounts: Object.entries(dailyCounts).map(([date, count]) => ({ date, count })),
    totalCalls: calls.length,
    successfulCalls,
    successRate: calls.length > 0 ? (successfulCalls / calls.length * 100).toFixed(1) : 0,
    avgDuration: Math.round(avgDuration / 1000), // Convert to seconds
    endReasons,
  };
};

module.exports = {
  createKnowledgeBase,
  fetchCallsOptimized,
  calculateDateRange,
  processCallsForCharts,
  LIMIT_CONFIG,
};
