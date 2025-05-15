
import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Brain, Bot, CircuitBoard, Radar, BotMessageSquare, Wand } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";

interface AIInsight {
  type: string;
  source: string;
  timestamp: string;
  confidence: number;
  description: string;
  status: "Active" | "Resolved" | "Investigating";
}

export const AIInsights = () => {
  const [insights, setInsights] = useState<AIInsight[]>([
    {
      type: "Anomaly",
      source: "Network Traffic",
      timestamp: "2023-05-14 08:42:15",
      confidence: 78,
      description: "Unusual outbound connections detected to IP 195.123.246.128",
      status: "Investigating"
    },
    {
      type: "Pattern",
      source: "Process Monitor",
      timestamp: "2023-05-14 08:40:22",
      confidence: 86,
      description: "Suspicious process tree identified: cmd.exe -> powershell.exe -> regsvr32.exe",
      status: "Investigating"
    },
    {
      type: "Behavior",
      source: "Filesystem Scanner",
      timestamp: "2023-05-14 08:30:42",
      confidence: 92,
      description: "Multiple file extension changes detected in Documents folder",
      status: "Active"
    }
  ]);
  
  const [modelStatus, setModelStatus] = useState({
    accuracy: 94.2,
    lastTrained: "2023-05-10 12:30:00",
    version: "1.2.3",
    samples: 14582,
    falsePositives: 2.8
  });

  const [aiMetrics, setAiMetrics] = useState({
    threatsPrevented: 18,
    anomaliesDetected: 47,
    averageConfidence: 82,
    learningRate: 0.05,
    activeLayers: 5
  });
  
  const [trainingProgress, setTrainingProgress] = useState(0);
  const [isTraining, setIsTraining] = useState(false);
  
  const startTraining = () => {
    setIsTraining(true);
    setTrainingProgress(0);
    
    // Simulate training progress
    const interval = setInterval(() => {
      setTrainingProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsTraining(false);
          return 100;
        }
        return prev + 2;
      });
    }, 200);
  };

  // Confidence color based on level
  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return "text-red-600 dark:text-red-400";
    if (confidence >= 70) return "text-orange-600 dark:text-orange-400";
    return "text-yellow-600 dark:text-yellow-400";
  };

  // Status badge color
  const getStatusColor = (status: string) => {
    switch (status) {
      case "Active": 
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
      case "Resolved": 
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
      case "Investigating":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">AI Insights & Analytics</h2>
        <div className="flex items-center space-x-2">
          <button className="px-3 py-1 rounded text-sm font-medium bg-gray-100 text-gray-800 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700">
            Settings
          </button>
          <button 
            className="px-3 py-1 rounded text-sm font-medium bg-purple-100 text-purple-800 hover:bg-purple-200 dark:bg-purple-900 dark:text-purple-200 dark:hover:bg-purple-800"
          >
            Advanced Options
          </button>
        </div>
      </div>
      
      {/* AI Model Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow bg-gradient-to-br from-white to-blue-50 dark:from-gray-900 dark:to-gray-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg flex items-center">
              <Brain className="h-5 w-5 mr-2 text-purple-500" />
              AI Model Status
            </CardTitle>
            <CardDescription>Current ML model performance metrics</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Accuracy:</span>
                <span className="text-sm font-bold text-green-600 dark:text-green-400">{modelStatus.accuracy}%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Last Training:</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{modelStatus.lastTrained}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Version:</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{modelStatus.version}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Training Samples:</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{modelStatus.samples.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">False Positive Rate:</span>
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{modelStatus.falsePositives}%</span>
              </div>
              <Button 
                variant="outline" 
                className="w-full mt-2 bg-purple-50 hover:bg-purple-100 text-purple-700 border-purple-200 dark:bg-purple-900/30 dark:border-purple-800 dark:text-purple-300 dark:hover:bg-purple-900/50"
                onClick={startTraining}
                disabled={isTraining}
              >
                <Wand className="h-4 w-4 mr-1" />
                {isTraining ? "Training..." : "Retrain Model"}
              </Button>
              
              {isTraining && (
                <div className="mt-2">
                  <div className="flex justify-between items-center text-xs mb-1">
                    <span className="text-gray-600 dark:text-gray-400">Training Progress</span>
                    <span className="font-medium text-purple-600 dark:text-purple-400">{trainingProgress}%</span>
                  </div>
                  <Progress value={trainingProgress} className="h-1.5 bg-purple-100 dark:bg-purple-900/30">
                    <div className="h-full bg-purple-500 dark:bg-purple-400 rounded-full"/>
                  </Progress>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow bg-gradient-to-br from-white to-blue-50 dark:from-gray-900 dark:to-gray-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg flex items-center">
              <CircuitBoard className="h-5 w-5 mr-2 text-blue-500" />
              AI Performance Metrics
            </CardTitle>
            <CardDescription>Real-time performance statistics</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <MetricItem 
                label="Threats Prevented" 
                value={aiMetrics.threatsPrevented} 
                icon={<Shield className="h-4 w-4 text-green-500" />} 
              />
              <MetricItem 
                label="Anomalies Detected" 
                value={aiMetrics.anomaliesDetected} 
                icon={<Radar className="h-4 w-4 text-yellow-500" />} 
              />
              <MetricItem 
                label="Avg. Confidence" 
                value={`${aiMetrics.averageConfidence}%`} 
                icon={<Bot className="h-4 w-4 text-blue-500" />} 
              />
              <MetricItem 
                label="Learning Rate" 
                value={aiMetrics.learningRate} 
                icon={<Brain className="h-4 w-4 text-purple-500" />} 
              />
              <MetricItem 
                label="Active Neural Layers" 
                value={aiMetrics.activeLayers} 
                icon={<CircuitBoard className="h-4 w-4 text-indigo-500" />} 
              />
              <Button variant="outline" className="w-full mt-2">
                View Detailed Analytics
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow bg-gradient-to-br from-white to-blue-50 dark:from-gray-900 dark:to-gray-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg flex items-center">
              <BotMessageSquare className="h-5 w-5 mr-2 text-indigo-500" />
              AI Anomaly Insights
            </CardTitle>
            <CardDescription>Latest AI-detected anomalies</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {insights.map((insight, idx) => (
                <div key={idx} className="p-3 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                  <div className="flex justify-between mb-1">
                    <span className="font-medium text-sm text-gray-900 dark:text-gray-100">{insight.type}</span>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(insight.status)}`}>
                      {insight.status}
                    </span>
                  </div>
                  <p className="text-sm text-gray-700 dark:text-gray-300 mb-1">{insight.description}</p>
                  <div className="flex justify-between text-xs">
                    <span className="text-gray-500 dark:text-gray-400">{insight.source} • {insight.timestamp}</span>
                    <span className={`font-medium ${getConfidenceColor(insight.confidence)}`}>
                      {insight.confidence}% confidence
                    </span>
                  </div>
                </div>
              ))}
            </div>
            <div className="p-2 bg-gray-50 dark:bg-gray-800/50 text-center">
              <button className="text-sm text-blue-600 dark:text-blue-400 hover:underline">
                View All Insights
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

interface MetricItemProps {
  label: string;
  value: number | string;
  icon?: React.ReactNode;
}

const MetricItem = ({ label, value, icon }: MetricItemProps) => (
  <div className="flex justify-between items-center">
    <div className="flex items-center">
      {icon && <span className="mr-2">{icon}</span>}
      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{label}:</span>
    </div>
    <span className="text-sm font-bold text-gray-900 dark:text-gray-100">{value}</span>
  </div>
);
