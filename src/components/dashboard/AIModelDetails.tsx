
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Microchip, Wand, CircuitBoard, Brain } from "lucide-react";

export const AIModelDetails = () => {
  const modelDetails = {
    architecture: "Hybrid Neural Network",
    parameters: "128M",
    inputFeatures: 42,
    outputClasses: 8,
    precisionLevel: "FP16",
    trainingEpochs: 250,
    processor: "WebGPU + CPU",
    inferenceTime: "45ms",
    memoryUsage: "84MB"
  };

  const algorithmTypes = [
    { name: "Anomaly Detection", percentage: 35 },
    { name: "Classification", percentage: 25 },
    { name: "Pattern Recognition", percentage: 20 },
    { name: "Forecasting", percentage: 15 },
    { name: "Clustering", percentage: 5 }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow bg-gradient-to-br from-white to-blue-50 dark:from-gray-900 dark:to-gray-800">
        <CardHeader>
          <CardTitle className="text-lg flex items-center">
            <Microchip className="h-5 w-5 mr-2 text-indigo-500" />
            AI Model Architecture
          </CardTitle>
          <CardDescription>Technical specifications of the detection model</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4">
            <DetailItem label="Architecture" value={modelDetails.architecture} />
            <DetailItem label="Parameters" value={modelDetails.parameters} />
            <DetailItem label="Input Features" value={modelDetails.inputFeatures} />
            <DetailItem label="Output Classes" value={modelDetails.outputClasses} />
            <DetailItem label="Precision" value={modelDetails.precisionLevel} />
            <DetailItem label="Training Epochs" value={modelDetails.trainingEpochs} />
            <DetailItem label="Processor" value={modelDetails.processor} />
            <DetailItem label="Inference Time" value={modelDetails.inferenceTime} />
            <DetailItem label="Memory Usage" value={modelDetails.memoryUsage} />
          </div>
        </CardContent>
      </Card>
      
      <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow bg-gradient-to-br from-white to-blue-50 dark:from-gray-900 dark:to-gray-800">
        <CardHeader>
          <CardTitle className="text-lg flex items-center">
            <Brain className="h-5 w-5 mr-2 text-purple-500" />
            AI Algorithm Breakdown
          </CardTitle>
          <CardDescription>Distribution of AI algorithm types</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {algorithmTypes.map((algo, idx) => (
              <div key={idx} className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{algo.name}</span>
                  <span className="text-sm font-medium text-gray-900 dark:text-gray-100">{algo.percentage}%</span>
                </div>
                <Progress value={algo.percentage} className="h-1.5">
                  <div className={`h-full rounded-full ${getColorForAlgorithm(algo.name)}`} />
                </Progress>
              </div>
            ))}
            <div className="mt-4 p-3 bg-purple-50 dark:bg-purple-900/30 rounded-md border border-purple-100 dark:border-purple-800">
              <div className="flex items-start">
                <Wand className="h-5 w-5 text-purple-600 dark:text-purple-400 mt-0.5 mr-2" />
                <div>
                  <h4 className="text-sm font-medium text-purple-800 dark:text-purple-300">Advanced AI Capabilities</h4>
                  <p className="text-xs text-purple-600 dark:text-purple-400 mt-1">
                    This system incorporates ensemble learning techniques with adaptive thresholds
                    for dynamic response to evolving threats. Neural network layers
                    are fine-tuned for ransomware-specific behavior patterns.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

interface DetailItemProps {
  label: string;
  value: string | number;
}

const DetailItem = ({ label, value }: DetailItemProps) => (
  <div className="flex flex-col">
    <span className="text-xs text-gray-500 dark:text-gray-400">{label}</span>
    <span className="font-medium text-gray-900 dark:text-gray-100">{value}</span>
  </div>
);

const getColorForAlgorithm = (name: string): string => {
  switch (name) {
    case "Anomaly Detection":
      return "bg-red-500 dark:bg-red-400";
    case "Classification":
      return "bg-blue-500 dark:bg-blue-400";
    case "Pattern Recognition":
      return "bg-green-500 dark:bg-green-400";
    case "Forecasting":
      return "bg-yellow-500 dark:bg-yellow-400";
    case "Clustering":
      return "bg-purple-500 dark:bg-purple-400";
    default:
      return "bg-gray-500 dark:bg-gray-400";
  }
};
