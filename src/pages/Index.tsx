import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Activity, FileText, Network, Cpu, AlertTriangle, Clock, Server, Database, Lock, Code, Terminal, Wifi, HardDrive, Scan, Users, AreaChart, WifiHigh, Bluetooth, BluetoothConnected, EthernetPort, Usb } from "lucide-react";
import { useState, useEffect } from "react";
import { Progress } from "@/components/ui/progress";
import { AIInsights } from "@/components/dashboard/AIInsights";
import { AIModelDetails } from "@/components/dashboard/AIModelDetails";

const Index = () => {
  const [systemStatus, setSystemStatus] = useState("Protected");
  const [lastScan, setLastScan] = useState("2023-05-14 08:30:22");
  const [threatsDetected, setThreatsDetected] = useState(0);
  const [scanningStatus, setScanningStatus] = useState("Idle");
  const [scanProgress, setScanProgress] = useState(0);
  const [cpuUsage, setCpuUsage] = useState(32);
  const [memoryUsage, setMemoryUsage] = useState(45);
  const [diskUsage, setDiskUsage] = useState(58);
  const [networkTraffic, setNetworkTraffic] = useState(12);
  const [scanDepth, setScanDepth] = useState("Normal");
  const [monitoredSystems, setMonitoredSystems] = useState(42);
  const [threatSeverity, setThreatSeverity] = useState("Low");
  const [discoveredDevices, setDiscoveredDevices] = useState({
    ethernet: 18,
    wifi: 12,
    bluetooth: 6,
    usb: 4,
    other: 2
  });
  
  const startScan = () => {
    setScanningStatus("Scanning");
    setScanProgress(0);
    // In a real implementation, this would trigger the scanning process
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setScanningStatus("Idle");
          setLastScan(new Date().toLocaleString());
          return 100;
        }
        return prev + 5;
      });
    }, 150);
  };

  useEffect(() => {
    // Simulate changing metrics
    const interval = setInterval(() => {
      setCpuUsage(Math.floor(Math.random() * 30) + 20);
      setMemoryUsage(Math.floor(Math.random() * 30) + 30);
      setNetworkTraffic(Math.floor(Math.random() * 20) + 5);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 dark:from-gray-900 dark:to-gray-800">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-md border-b border-gray-200 dark:border-gray-700">
        <div className="container mx-auto px-4 py-6">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3">
              <Shield className="h-10 w-10 text-blue-600 dark:text-blue-400" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 flex items-center">
                  RansomEye Guardian
                  <span className="ml-2 text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 px-2 py-0.5 rounded">v1.2.0</span>
                </h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">Advanced Ransomware Detection Platform</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <div className={`px-3 py-1 rounded-full text-sm font-medium ${
                systemStatus === "Protected" 
                  ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 border border-green-200 dark:border-green-800" 
                  : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border border-red-200 dark:border-red-800"
              }`}>
                <div className="flex items-center">
                  <div className={`h-2 w-2 rounded-full mr-1 ${systemStatus === "Protected" ? "bg-green-500" : "bg-red-500"}`}></div>
                  {systemStatus}
                </div>
              </div>
              <Button 
                onClick={startScan} 
                disabled={scanningStatus === "Scanning"} 
                className="ml-2 bg-blue-600 hover:bg-blue-700 text-white"
              >
                <Scan className="h-4 w-4 mr-1" />
                {scanningStatus === "Scanning" ? "Scanning..." : "Start Scan"}
              </Button>
              <select 
                className="ml-2 border border-gray-300 dark:border-gray-600 rounded px-2 py-1.5 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 text-sm"
                value={scanDepth}
                onChange={(e) => setScanDepth(e.target.value)}
              >
                <option value="Quick">Quick Scan</option>
                <option value="Normal">Normal Scan</option>
                <option value="Deep">Deep Scan</option>
                <option value="Custom">Custom Scan</option>
              </select>
            </div>
          </div>
          
          {/* Scan Progress */}
          {scanningStatus === "Scanning" && (
            <div className="mt-4">
              <div className="flex justify-between items-center mb-1">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Scan Progress</span>
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} className="h-2" />
            </div>
          )}
        </div>
      </header>

      {/* Main content */}
      <main className="container mx-auto px-4 py-8">
        {/* Overview section */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <Activity className="h-5 w-5 mr-2 text-blue-500" />
                System Status
              </CardTitle>
              <CardDescription>Current security posture</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex justify-between items-center">
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-gray-100">{systemStatus}</div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Last scan: {lastScan}</p>
                </div>
                <div className={`h-12 w-12 rounded-full flex items-center justify-center ${
                  systemStatus === "Protected" 
                    ? "bg-green-100 dark:bg-green-900" 
                    : "bg-red-100 dark:bg-red-900"
                }`}>
                  <Shield className={`h-6 w-6 ${
                    systemStatus === "Protected" 
                      ? "text-green-600 dark:text-green-400" 
                      : "text-red-600 dark:text-red-400"
                  }`} />
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <AlertTriangle className="h-5 w-5 mr-2 text-yellow-500" />
                Threats
              </CardTitle>
              <CardDescription>Detected security issues</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex justify-between items-center">
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-gray-100">{threatsDetected}</div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Severity: <span className={`font-medium ${
                      threatSeverity === "Low" ? "text-green-600 dark:text-green-400" :
                      threatSeverity === "Medium" ? "text-yellow-600 dark:text-yellow-400" : 
                      "text-red-600 dark:text-red-400"
                    }`}>{threatSeverity}</span>
                  </p>
                </div>
                <div className={`h-12 w-12 rounded-full flex items-center justify-center ${
                  threatsDetected === 0 
                    ? "bg-green-100 dark:bg-green-900" 
                    : "bg-yellow-100 dark:bg-yellow-900"
                }`}>
                  <AlertTriangle className={`h-6 w-6 ${
                    threatsDetected === 0 
                      ? "text-green-600 dark:text-green-400" 
                      : "text-yellow-600 dark:text-yellow-400"
                  }`} />
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <FileText className="h-5 w-5 mr-2 text-green-500" />
                Reports
              </CardTitle>
              <CardDescription>Generated security reports</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex justify-between items-center">
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-gray-100">3</div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    Last generated: <span className="font-medium">Today</span>
                  </p>
                </div>
                <div className="h-12 w-12 rounded-full flex items-center justify-center bg-green-100 dark:bg-green-900">
                  <FileText className="h-6 w-6 text-green-600 dark:text-green-400" />
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg flex items-center">
                <Users className="h-5 w-5 mr-2 text-indigo-500" />
                Monitored Systems
              </CardTitle>
              <CardDescription>Connected endpoints</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex justify-between items-center">
                <div>
                  <div className="text-2xl font-bold text-gray-900 dark:text-gray-100">{monitoredSystems}</div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    <span className="text-green-600 dark:text-green-400">36 online</span> • 6 offline
                  </p>
                </div>
                <div className="h-12 w-12 rounded-full flex items-center justify-center bg-indigo-100 dark:bg-indigo-900">
                  <Users className="h-6 w-6 text-indigo-600 dark:text-indigo-400" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* AI Analytics Section - NEW */}
        <h2 className="text-xl font-bold mb-4 text-gray-900 dark:text-gray-100">AI Analytics</h2>
        <div className="mb-8">
          <AIInsights />
        </div>
        
        {/* AI Model Details Section - NEW */}
        <h2 className="text-xl font-bold mb-4 text-gray-900 dark:text-gray-100">AI Model Details</h2>
        <div className="mb-8">
          <AIModelDetails />
        </div>

        {/* Resource Usage Section */}
        <h2 className="text-xl font-bold mb-4 text-gray-900 dark:text-gray-100">System Resources</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <ResourceCard 
            title="CPU Usage" 
            value={cpuUsage} 
            icon={<Cpu className="h-5 w-5 text-blue-500" />} 
            color="blue"
            unit="%" 
          />
          <ResourceCard 
            title="Memory Usage" 
            value={memoryUsage} 
            icon={<Server className="h-5 w-5 text-purple-500" />} 
            color="purple"
            unit="%" 
          />
          <ResourceCard 
            title="Disk Usage" 
            value={diskUsage} 
            icon={<HardDrive className="h-5 w-5 text-green-500" />} 
            color="green"
            unit="%" 
          />
          <ResourceCard 
            title="Network Traffic" 
            value={networkTraffic} 
            icon={<Wifi className="h-5 w-5 text-yellow-500" />} 
            color="yellow"
            unit="MB/s" 
          />
        </div>

        {/* Network Discovery Section */}
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Connected Devices</h2>
          <div className="flex items-center space-x-2">
            <button className="px-3 py-1 rounded text-sm font-medium bg-gray-100 text-gray-800 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700">
              Refresh Scan
            </button>
            <button className="px-3 py-1 rounded text-sm font-medium bg-blue-100 text-blue-800 hover:bg-blue-200 dark:bg-blue-900 dark:text-blue-200 dark:hover:bg-blue-800">
              Export Device List
            </button>
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
          <ConnectionCard 
            title="Ethernet" 
            icon={<EthernetPort className="h-5 w-5 text-blue-500" />}
            deviceCount={discoveredDevices.ethernet}
            status="Active"
            lastScan="2 minutes ago"
          />
          <ConnectionCard 
            title="WiFi" 
            icon={<WifiHigh className="h-5 w-5 text-green-500" />}
            deviceCount={discoveredDevices.wifi}
            status="Active"
            lastScan="5 minutes ago"
          />
          <ConnectionCard 
            title="Bluetooth" 
            icon={<BluetoothConnected className="h-5 w-5 text-indigo-500" />}
            deviceCount={discoveredDevices.bluetooth}
            status="Active" 
            lastScan="8 minutes ago"
          />
          <ConnectionCard 
            title="USB" 
            icon={<Usb className="h-5 w-5 text-purple-500" />}
            deviceCount={discoveredDevices.usb}
            status="Active"
            lastScan="10 minutes ago"
          />
          <ConnectionCard 
            title="Other" 
            icon={<Network className="h-5 w-5 text-yellow-500" />}
            deviceCount={discoveredDevices.other}
            status="Active"
            lastScan="15 minutes ago"
          />
        </div>

        {/* Modules section */}
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Monitoring Modules</h2>
          <div className="flex items-center space-x-2">
            <button className="px-3 py-1 rounded text-sm font-medium bg-gray-100 text-gray-800 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700">
              Configure
            </button>
            <button className="px-3 py-1 rounded text-sm font-medium bg-blue-100 text-blue-800 hover:bg-blue-200 dark:bg-blue-900 dark:text-blue-200 dark:hover:bg-blue-800">
              Check for updates
            </button>
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          <ModuleCard 
            title="Filesystem Scanner" 
            icon={<FileText className="h-5 w-5 text-blue-500" />} 
            status="Active" 
            description="Monitors filesystem for suspicious activities" 
            lastUpdated="10 minutes ago"
            detections={0}
            isAI={false}
          />
          <ModuleCard 
            title="Process Monitor" 
            icon={<Cpu className="h-5 w-5 text-purple-500" />} 
            status="Active" 
            description="Detects suspicious process behaviors" 
            lastUpdated="5 minutes ago"
            detections={0}
            isAI={false}
          />
          <ModuleCard 
            title="Network Sniffer" 
            icon={<Network className="h-5 w-5 text-green-500" />} 
            status="Active" 
            description="Analyzes network traffic for threats" 
            lastUpdated="2 minutes ago"
            detections={0}
            isAI={false}
          />
          <ModuleCard 
            title="Persistence Scanner" 
            icon={<Lock className="h-5 w-5 text-yellow-500" />} 
            status="Active" 
            description="Checks for persistence mechanisms" 
            lastUpdated="15 minutes ago"
            detections={0}
            isAI={false}
          />
          <ModuleCard 
            title="Auto Scanner" 
            icon={<Activity className="h-5 w-5 text-red-500" />} 
            status="Active" 
            description="Periodically scans system components" 
            lastUpdated="30 minutes ago"
            detections={0}
            isAI={false}
          />
          <ModuleCard 
            title="AI Anomaly Engine" 
            icon={<AreaChart className="h-5 w-5 text-indigo-500" />} 
            status="Active" 
            description="Uses ML to detect anomalies" 
            lastUpdated="1 minute ago"
            detections={0}
            isAI={true}
          />
        </div>

        {/* Recent Activity */}
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Recent Activity</h2>
          <button className="px-3 py-1 rounded text-sm font-medium bg-gray-100 text-gray-800 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700">
            View all logs
          </button>
        </div>
        <Card className="border border-gray-200 dark:border-gray-700 shadow-sm mb-8">
          <CardContent className="p-0 overflow-auto">
            <table className="w-full">
              <thead className="bg-gray-100 dark:bg-gray-800 sticky top-0">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Module</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Event</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
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
        
        {/* System Information */}
        <h2 className="text-xl font-bold mb-4 text-gray-900 dark:text-gray-100">System Information</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <Card className="border border-gray-200 dark:border-gray-700 shadow-sm">
            <CardHeader>
              <CardTitle className="text-lg flex items-center">
                <Terminal className="h-5 w-5 mr-2 text-gray-500" />
                Environment Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <InfoItem label="Hostname" value="ransomeye-guardian-01" />
                <InfoItem label="OS" value="Ubuntu 22.04 LTS" />
                <InfoItem label="Kernel" value="5.15.0-48-generic" />
                <InfoItem label="Architecture" value="x86_64" />
                <InfoItem label="Python Version" value="3.10.4" />
                <InfoItem label="Database" value="SQLite 3.37.2" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="border border-gray-200 dark:border-gray-700 shadow-sm">
            <CardHeader>
              <CardTitle className="text-lg flex items-center">
                <Database className="h-5 w-5 mr-2 text-gray-500" />
                Database Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <InfoItem label="Status" value="Connected" />
                <InfoItem label="Size" value="42.3 MB" />
                <InfoItem label="Records" value="12,458" />
                <InfoItem label="Last Backup" value="2023-05-14 00:00:00" />
                <InfoItem label="Backup Size" value="38.1 MB" />
                <InfoItem label="Retention Policy" value="30 days" />
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
      
      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 py-4">
        <div className="container mx-auto px-4">
          <div className="flex justify-between items-center">
            <div className="text-sm text-gray-600 dark:text-gray-400">
              © 2023 RansomEye Guardian Platform. Version 1.2.0
            </div>
            <div className="flex space-x-4">
              <button className="text-sm text-blue-600 dark:text-blue-400 hover:underline">Documentation</button>
              <button className="text-sm text-blue-600 dark:text-blue-400 hover:underline">Support</button>
              <button className="text-sm text-blue-600 dark:text-blue-400 hover:underline">About</button>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

// Helper component for module cards
const ModuleCard = ({ title, icon, status, description, lastUpdated, detections, isAI }) => (
  <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
    <CardHeader className="pb-2">
      <CardTitle className="text-lg flex items-center">
        {icon}
        <span className="ml-2">{title}</span>
        {isAI && (
          <span className="ml-2 px-1.5 py-0.5 rounded-md text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
            AI
          </span>
        )}
      </CardTitle>
      <CardDescription>{description}</CardDescription>
    </CardHeader>
    <CardContent>
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Status:</span>
          <span className={`px-2 py-1 text-xs font-medium rounded ${
            status === "Active" ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" : 
            "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
          }`}>
            {status}
          </span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <span className="text-gray-600 dark:text-gray-400">Last updated:</span>
          <span className="font-medium text-gray-800 dark:text-gray-200">{lastUpdated}</span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <span className="text-gray-600 dark:text-gray-400">Detections:</span>
          <span className={`font-medium ${detections > 0 ? "text-yellow-600 dark:text-yellow-400" : "text-gray-800 dark:text-gray-200"}`}>
            {detections}
          </span>
        </div>
      </div>
    </CardContent>
  </Card>
);

// New helper component for connection cards
const ConnectionCard = ({ title, icon, deviceCount, status, lastScan }) => (
  <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
    <CardHeader className="pb-2">
      <CardTitle className="text-lg flex items-center">
        {icon}
        <span className="ml-2">{title}</span>
      </CardTitle>
    </CardHeader>
    <CardContent>
      <div className="space-y-3">
        <div className="flex items-center justify-center">
          <span className="text-3xl font-bold text-gray-800 dark:text-gray-200">{deviceCount}</span>
          <span className="ml-2 text-sm text-gray-600 dark:text-gray-400">devices</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Status:</span>
          <span className={`px-2 py-1 text-xs font-medium rounded ${
            status === "Active" ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" : 
            "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
          }`}>
            {status}
          </span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <span className="text-gray-600 dark:text-gray-400">Last scan:</span>
          <span className="font-medium text-gray-800 dark:text-gray-200">{lastScan}</span>
        </div>
        <Button variant="outline" className="w-full text-sm py-1" size="sm">
          View Details
        </Button>
      </div>
    </CardContent>
  </Card>
);

// Helper component for activity rows
const ActivityRow = ({ time, module, event, status }) => (
  <tr className="hover:bg-gray-50 dark:hover:bg-gray-800">
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
    <td className="px-4 py-3 text-sm">
      <button className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 mr-3">
        Details
      </button>
    </td>
  </tr>
);

// Helper component for resource cards
const ResourceCard = ({ title, value, icon, color, unit }) => {
  const getColorClass = (color, value) => {
    const baseClasses = {
      blue: {
        bg: "bg-blue-100 dark:bg-blue-900",
        text: "text-blue-600 dark:text-blue-400",
        bar: "bg-blue-500 dark:bg-blue-400",
      },
      green: {
        bg: "bg-green-100 dark:bg-green-900",
        text: "text-green-600 dark:text-green-400",
        bar: "bg-green-500 dark:bg-green-400",
      },
      purple: {
        bg: "bg-purple-100 dark:bg-purple-900",
        text: "text-purple-600 dark:text-purple-400",
        bar: "bg-purple-500 dark:bg-purple-400",
      },
      yellow: {
        bg: "bg-yellow-100 dark:bg-yellow-900",
        text: "text-yellow-600 dark:text-yellow-400",
        bar: "bg-yellow-500 dark:bg-yellow-400",
      },
    };
    
    return baseClasses[color] || baseClasses.blue;
  };
  
  const colorClass = getColorClass(color, value);
  
  return (
    <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg flex items-center">
          {icon}
          <span className="ml-2">{title}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center mb-2">
          <div className="text-2xl font-bold mr-1 text-gray-900 dark:text-gray-100">{value}</div>
          <div className="text-sm text-gray-500 dark:text-gray-400">{unit}</div>
        </div>
        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
          <div 
            className={`${colorClass.bar} h-2 rounded-full`} 
            style={{ width: `${value}%` }}
          ></div>
        </div>
      </CardContent>
    </Card>
  );
};

// Helper component for info items
const InfoItem = ({ label, value }) => (
  <div className="flex flex-col">
    <span className="text-sm text-gray-500 dark:text-gray-400">{label}</span>
    <span className="font-medium text-gray-900 dark:text-gray-100">{value}</span>
  </div>
);

export default Index;
