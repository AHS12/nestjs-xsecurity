import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { cli } from '../cli/x-security.install';

// Mock fs and path modules
jest.mock('fs');
jest.mock('path');
jest.mock('crypto');

// Mock console methods
const mockConsoleLog = jest.spyOn(console, 'log').mockImplementation();
const mockConsoleError = jest.spyOn(console, 'error').mockImplementation();

describe('CLI', () => {
  // Store original process.exit
  const originalProcessExit = process.exit;

  // Mock implementation for path.join
  const mockPathJoin = path.join as jest.Mock;
  mockPathJoin.mockImplementation((...args) => args.join('/'));

  beforeAll(() => {
    // Mock process.exit before all tests
    process.exit = jest.fn() as never;
  });

  afterAll(() => {
    // Restore original process.exit after all tests
    process.exit = originalProcessExit;
  });

  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();

    // Reset fs mock implementation
    (fs.existsSync as jest.Mock).mockReset();
    (fs.readFileSync as jest.Mock).mockReset();
    (fs.writeFileSync as jest.Mock).mockReset();

    // Mock crypto.randomBytes with a predictable value
    (crypto.randomBytes as jest.Mock).mockReturnValue(Buffer.from('mockSecret'));
  });

  describe('help command', () => {
    it('should show help message when no command is provided', () => {
      cli([]);
      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.stringContaining('nestjs-xsecurity <command>'),
      );
      expect(process.exit).not.toHaveBeenCalled();
    });

    it('should show help message with --help flag', () => {
      cli(['--help']);
      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.stringContaining('nestjs-xsecurity <command>'),
      );
      expect(process.exit).not.toHaveBeenCalled();
    });

    it('should show error for unknown command and exit with code 1', () => {
      cli(['unknown']);
      expect(mockConsoleError).toHaveBeenCalledWith(
        expect.stringContaining('Unknown command: unknown'),
      );
      expect(process.exit).toHaveBeenCalledWith(1);
    });
  });

  describe('install/init command', () => {
    it('should generate secret and update env file when it does not exist', () => {
      (fs.existsSync as jest.Mock).mockReturnValue(false);
      (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

      cli(['install']);

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('XSECURITY_SECRET='),
      );
      expect(mockConsoleLog).toHaveBeenCalledWith(expect.stringContaining('Generated secret:'));
      expect(mockConsoleLog).toHaveBeenCalledWith(
        expect.stringContaining('✓ Updated .env file successfully'),
      );
      expect(process.exit).not.toHaveBeenCalled();
    });

    it('should update existing env file with new secret', () => {
      (fs.existsSync as jest.Mock).mockReturnValue(true);
      (fs.readFileSync as jest.Mock).mockReturnValue('EXISTING_VAR=value\n');
      (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

      cli(['init']);

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('XSECURITY_SECRET='),
      );
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('EXISTING_VAR=value'),
      );
      expect(process.exit).not.toHaveBeenCalled();
    });

    it('should handle file write errors gracefully', () => {
      (fs.existsSync as jest.Mock).mockReturnValue(true);
      (fs.readFileSync as jest.Mock).mockReturnValue('');
      (fs.writeFileSync as jest.Mock).mockImplementation(() => {
        throw new Error('Write error');
      });
      cli(['install']);

      expect(mockConsoleError).toHaveBeenCalledWith('Error: Could not write to .env file');
      expect(mockConsoleError).toHaveBeenCalledWith(
        'Please add the following lines to your .env file manually:',
      );
      expect(mockConsoleLog).toHaveBeenCalledWith(expect.stringContaining('Generated secret:'));
      expect(mockConsoleLog).toHaveBeenCalledWith('\n✨ XSecurity configured successfully!');
      expect(mockConsoleLog).toHaveBeenCalledWith(
        'Make sure to add these environment variables to your production environment.\n',
      );
    });

    it('should replace existing XSECURITY variables in env file', () => {
      const existingEnv = 'XSECURITY_SECRET=old-secret\nXSECURITY_ENABLED=false\n';
      (fs.existsSync as jest.Mock).mockReturnValue(true);
      (fs.readFileSync as jest.Mock).mockReturnValue(existingEnv);

      const writeFileSpy = (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

      cli(['install']);

      const writtenContent = writeFileSpy.mock.calls[0][1];
      expect(writtenContent).toMatch(/XSECURITY_SECRET=.*\n/);
      expect(writtenContent).toMatch(/XSECURITY_ENABLED=true\n/);
      expect(writtenContent.match(/XSECURITY_SECRET/g)).toHaveLength(1);
      expect(writtenContent.match(/XSECURITY_ENABLED/g)).toHaveLength(1);
      expect(process.exit).not.toHaveBeenCalled();
    });
  });
});
