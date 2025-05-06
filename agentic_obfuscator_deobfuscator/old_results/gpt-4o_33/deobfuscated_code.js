const arrayValues = [
  "TkFvek=",
  "Rm5pcA==",
  "VGhpcw==",
  "SGVpbg==",
  "S0VZNQ==",
  "YWJjZGVmZw==",
  "Z2l0",
  "Z3JlYXRlcw==",
  "ZXZhbA==",
  "YWxlcnQ=",
];

(function (hexArray, rotateBy) {
  const rotate = function (times) {
    while (--times) {
      hexArray.push(hexArray.shift());
    }
  };
  rotate(++rotateBy);
})(arrayValues, 271);

const decodeBase64 = function (index) {
  index = index - 0;
  let str = arrayValues[index];
  return atob(str);
};

(function () {
  const obfuscationHandlers = {
    token: decodeBase64("0"),
    encrypt: decodeBase64("1"),
    message: function (callback, parameters) {
      return callback(parameters);
    },
    calculate: function (a, b) {
      return a + b;
    },
    alertHandler: function (alertFunc) {
      return alertFunc();
    },
  };
  console.log(obfuscationHandlers.token); // Outputs: NAoz
  obfuscationHandlers.alertHandler(() => alert(decodeBase64("9")));
})();

// Class for a sample task
class TaskManager {
  constructor(taskName, taskCount = 0) {
    this.taskName = taskName;
    this.taskCount = taskCount;
  }

  addTask(count) {
    if (count > 0) {
      this.taskCount += count;
      console.log(`Task ${this.taskName} added: ${count} new tasks, total: ${this.taskCount}`);
    } else {
      console.log("Invalid number of tasks to add");
    }
  }

  removeTask(count) {
    if (count > 0 && count <= this.taskCount) {
      this.taskCount -= count;
      console.log(`Task ${this.taskName} removed: ${count} tasks, remaining: ${this.taskCount}`);
    } else {
      console.log("Error: Cannot remove more tasks than available.");
    }
  }

  transferTasks(count, targetManager) {
    if (count > 0 && count <= this.taskCount) {
      this.removeTask(count);
      targetManager.addTask(count);
      console.log(`Transferred ${count} tasks from ${this.taskName} to ${targetManager.taskName}.`);
    } else {
      console.log("Error: Cannot transfer more tasks than available.");
    }
  }

  showTasks() {
    console.log(`${this.taskName} has ${this.taskCount} tasks total.`);
  }
}

// Create task managers
const manager1 = new TaskManager("Download Manager", 1000);
const manager2 = new TaskManager("Upload Manager", 500);

manager1.addTask(200);
manager1.removeTask(150);

setInterval(() => {
  manager1.showTasks();
  manager2.showTasks();
}, 60000);

manager2.addTask(300);
manager1.transferTasks(500, manager2);

class TaskList {
  constructor() {
    this.tasks = [];
  }

  addTask(task) {
    this.tasks.push(task);
  }

  showAllTasks() {
    if (this.tasks.length === 0) {
      console.log("No tasks available");
    } else {
      console.log("Task list:");
      this.tasks.forEach((task, index) => {
        console.log(`${index + 1}. ${task}`);
      });
    }
  }
}

// Create and show task list
const taskList = new TaskList();
taskList.addTask("Task 1: Initialize");
taskList.addTask("Task 2: Execute");
taskList.addTask("Task 3: Terminate");
taskList.addTask("Task 4: Complete");
taskList.showAllTasks();
