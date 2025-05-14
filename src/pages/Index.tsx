
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Activity, FileText, Network, Cpu, AlertTriangle } from "lucide-react";
import { useState } from "react";

const Index = () => {
  const [systemStatus, setSystemStatus] = useState("Protected");
  const [lastScan, setLastScan] = useState("2023-05-14 08:30:22");
  const [threatsDetected, setThreatsDetected] = useState(0);
  const [scanningStatus, setScanningStatus] = useState("Idle");
  
  const startScan = () => {
    setScanningStatus("Scanning");
    // In a real implementation, this would trigger the scanning process
    setTimeout(() => {
      setScanningStatus("Idle");
      setLastScan(new Date().toLocaleString());
    }, 3000);
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm">
        <div className="container mx-auto px-4 py-6">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600 dark:text-blue-400" />
              <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">RansomEye Guardian Platform</h1>
            </div>
            <div className="flex items-center space-x-2">
              <div className={`px-3 py-1 rounded-full text-sm font-medium ${systemStatus === "Protected" ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"}`}>
                {systemStatus}
              </div>
              <Button onClick={startScan} disabled={scanningStatus === "Scanning"} className="ml-2">
                {scanningStatus === "Scanning" ? "Scanning..." : "Start Scan"}
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="container mx-auto px-4 py-8">
        {/* Overview section */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <Activity className="h-5 w-5 mr-2 text-blue-500" />
                System Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{systemStatus}</div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Last scan: {lastScan}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <AlertTriangle className="h-5 w-5 mr-2 text-yellow-500" />
                Threats Detected
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{threatsDetected}</div>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {threatsDetected === 0 ? "No threats found" : `${threatsDetected} potential threats`}
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <FileText className="h-5 w-5 mr-2 text-green-500" />
                Reports
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">3</div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Available reports</p>
            </CardContent>
          </Card>
        </div>

        {/* Modules section */}
        <h2 className="text-xl font-bold mb-4 text-gray-900 dark:text-gray-100">Monitoring Modules</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          <ModuleCard 
            title="Filesystem Scanner" 
            icon={<FileText className="h-5 w-5 text-blue-500" />} 
            status="Active" 
            description="Monitors filesystem for suspicious activities" 
          />
          <ModuleCard 
            title="Process Monitor" 
            icon={<Cpu className="h-5 w-5 text-purple-500" />} 
            status="Active" 
            description="Detects suspicious process behaviors" 
          />
          <ModuleCard 
            title="Network Sniffer" 
            icon={<Network className="h-5 w-5 text-green-500" />} 
            status="Active" 
            description="Analyzes network traffic for threats" 
          />
          <ModuleCard 
            title="Persistence Scanner" 
            icon={<FileText className="h-5 w-5 text-yellow-500" />} 
            status="Active" 
            description="Checks for persistence mechanisms" 
          />
          <ModuleCard 
            title="Auto Scanner" 
            icon={<Activity className="h-5 w-5 text-red-500" />} 
            status="Active" 
            description="Periodically scans system components" 
          />
          <ModuleCard 
            title="AI Anomaly Engine" 
            icon={<Cpu className="h-5 w-5 text-indigo-500" />} 
            status="Active" 
            description="Uses ML to detect anomalies" 
          />
        </div>

        {/* Recent Activity */}
        <h2 className="text-xl font-bold mb-4 text-gray-900 dark:text-gray-100">Recent Activity</h2>
        <Card>
          <CardContent className="p-0">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Module</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Event</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                <ActivityRow time="08:30:22" module="System" event="System startup" status="Info" />
                <ActivityRow time="08:30:24" module="Filesystem Scanner" event="Scanner initialized" status="Info" />
                <ActivityRow time="08:30:25" module="Process Monitor" event="Monitor initialized" status="Info" />
                <ActivityRow time="08:30:26" module="Network Sniffer" event="Sniffer initialized" status="Info" />
                <ActivityRow time="08:32:15" module="Auto Scanner" event="Routine scan started" status="Info" />
                <ActivityRow time="08:35:42" module="Auto Scanner" event="Scan completed - No threats detected" status="Success" />
              </tbody>
            </table>
          </CardContent>
        </Card>
      </main>
    </div>
  );
};

// Helper component for module cards
const ModuleCard = ({ title, icon, status, description }) => (
  <Card>
    <CardHeader className="pb-2">
      <CardTitle className="text-lg flex items-center">
        {icon}
        <span className="ml-2">{title}</span>
      </CardTitle>
      <CardDescription>{description}</CardDescription>
    </CardHeader>
    <CardContent>
      <div className="flex items-center">
        <span className="text-sm font-medium">Status:</span>
        <span className={`ml-2 px-2 py-1 text-xs font-medium rounded ${
          status === "Active" ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" : 
          "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
        }`}>
          {status}
        </span>
      </div>
    </CardContent>
  </Card>
);

// Helper component for activity rows
const ActivityRow = ({ time, module, event, status }) => (
  <tr>
    <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{time}</td>
    <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100">{module}</td>
    <td className="px-4 py-3 text-sm text-gray-900 dark:text-gray-100">{event}</td>
    <td className="px-4 py-3 text-sm">
      <span className={`px-2 py-1 text-xs font-medium rounded ${
        status === "Info" ? "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200" : 
        status === "Success" ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" :
        status === "Warning" ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200" :
        "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
      }`}>
        {status}
      </span>
    </td>
  </tr>
);

export default Index;
