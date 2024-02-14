// CMakeProject1.cpp: определяет точку входа для приложения.
//

#include "CMakeProject1.h"

#include <filesystem>
#include <fstream>
#include <QtXml/qdom.h>

#include <QFile>
#include <yara.h>
using namespace std;
// Структура для узла в дереве
namespace fs = std::filesystem;
const 	QString ruleString = R"(
        rule %1
        {
            strings:
                %2
            condition:
                %3
			meta:
                FileType = %4
                Ext = %5
				Mime = %6
				FileName=%7
        }
    )";
QString parseXml(QDomDocument& doc,int& id,const std::string& filename) {
	//QString rules = ruleString;
	QString tab = "\n\t\t\t\t";
	QDomElement root = doc.documentElement();
	QString FileType = root.firstChildElement("Info").firstChildElement("FileType").text();
	QString Ext = root.firstChildElement("Info").firstChildElement("Ext").text();
	QString Mime = root.firstChildElement("Info").firstChildElement("Mime").text();
	auto n = root.firstChildElement("FrontBlock").elementsByTagName("Pattern");
	QString pattern;
	QString condition;
	//QStringList patterns;
	//QVector<int> positions;
	int ves(0);
	int last_position(0);
	for (int i = 0; i < n.count(); ++i) 
	{
		int pos = n.at(i).toElement().firstChildElement("Pos").text().toInt();
		auto bytes = n.at(i).toElement().firstChildElement("Bytes").text();
		
		if (i != 0&& (pos - last_position)>0)
		pattern += QString("[%1]").arg(pos-last_position );
		pattern += bytes;
		last_position = pos+ bytes.size()/2;
		/*pattern += tab+QString("$hex_string%1={%2}").arg(i).arg();
		if (i == 0)
			condition += tab+QString("($hex_string%1 at %2").arg(i).arg(pos);
		else 
			condition += tab+QString(" and $hex_string%1 at ($hex_string0+%2)").arg(i).arg(pos);*/

	}
	ves += n.count();
	pattern = tab + QString("$hex_string={%2}").arg(pattern);
	condition = tab + QString("$hex_string");
	n = root.firstChildElement("GlobalStrings").elementsByTagName("String");
	ves+= n.count();
	if (n.count() > 0)
		condition += " and (";
	for (int i = 0; i < n.count(); ++i)
	{
		pattern += tab+QString("$text_string%1=\"%2\"").arg(i).arg(n.at(i).toElement().text());
		if (i == 0)
			condition +=  QString("$text_string%1").arg(i);
		else
			condition += tab+QString(" and $text_string%1").arg(i);

	}
	if (n.count() > 0)
		condition += ")";
	QString rules=QString(R"(rule %1
        {
			meta:
                FileType = "%4"
                Ext = "%5"
				Mime = "%6"
				FileName="%7"
				Weight="%8"
            strings:%2
            condition:%3

        })").arg(QString("Rules%1").arg(id), pattern, condition, FileType, Ext, Mime, QString::fromStdString(filename),QString::number(ves));
	id++;
	if (Ext.contains("PDF")|| Ext.contains("pdf"))
		std::cout << rules.toStdString() << endl;
	return rules;
	
}
void my_callback(
	int error_level,
	const char* file_name,
	int line_number,
	const char* message,
	void* user_data)
{
	
		switch (error_level)
		{
		case YARA_ERROR_LEVEL_ERROR:
			std::cout << "[error]" <<"line:"<< line_number << message << endl;
			break;
		case YARA_ERROR_LEVEL_WARNING:
			//std::cout << "[warning]" << "line:"<<line_number << message << endl;
			break;
		default:
			break;
		}
	
}
int callback_function(
	YR_SCAN_CONTEXT* context,
	int message,
	void* message_data,
	void* user_data)
 {
	YR_RULE* yar = nullptr;
	switch (message)
	{
	case CALLBACK_MSG_RULE_MATCHING:
		 yar = (YR_RULE*)message_data;
		 std::cout << "FileType:" << yar->metas[0].string<< std::setw(10) << "Ext:" << yar->metas[1].string << std::setw(10) << "Mime:" << yar->metas[2].string << std::setw(10) << "FileName:" << yar->metas[3].string << std::setw(10) << "Ves:" << yar->metas[4].string << std::setw(10) << std::endl;
		break;
	case CALLBACK_MSG_RULE_NOT_MATCHING:
		 yar = (YR_RULE*)message_data;
		break;
	case		CALLBACK_MSG_SCAN_FINISHED:
		
		break;
	case		CALLBACK_MSG_IMPORT_MODULE:
		break;
	case		CALLBACK_MSG_MODULE_IMPORTED:
		break;
	default:
		break;
	}
	
	return CALLBACK_CONTINUE;
}
int main()
{
	std::string directoryPathStr = "D:\\Temp\\defs";
	fs::path directoryPath(directoryPathStr);

	int id(0);

	yr_initialize();
	std::vector<YR_RULE> rule;
	YR_RULES* rules =nullptr;
	YR_COMPILER* compiler=nullptr;
	yr_compiler_create(&compiler);
	yr_compiler_set_callback(compiler, (YR_COMPILER_CALLBACK_FUNC)my_callback, nullptr);

		for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
			if (entry.is_directory())
				continue;
			std::string filename = entry.path().u8string();
			QByteArray file;
			if (std::ifstream is{ filename, std::ios::binary }) {
				is.seekg(0, std::ios::end);
				auto size = is.tellg();
				//std::string str(size, '\0'); // construct string to stream size
				file.resize(size);
				is.seekg(0);
				if (is.read((char*)file.data(), size))
				{

					//  std::filesystem::remove(dir_entry.path());
				}
			}
			QDomDocument doc;
			if (!doc.setContent(file)) {
				std::cout << "Failed to parse XML content from file:" << filename;
				//file.close();
				return 0;
			}
			
			if (id == 98||id==1904||id==1905||id==4823||id>1000)
			{
				id++;
				continue;
			}
			auto obj=parseXml(doc,id, entry.path().filename().u8string()).toStdString();
			try
			{

			
			if (yr_compiler_add_string(compiler, obj.c_str(), nullptr) != 0)
			{
				int len(512);
				char* err=new char[len];				
				auto msg=yr_compiler_get_error_message(compiler, err, len);
				std::cout << "Error compile:" << filename << "id:" << id - 1 <<"message:"<<msg<< endl;
				delete[] err;
				
			}
			}
			catch (...)
			{
				continue;
			}
			//yr_rule_disable()
			//std::cout << obj.dump();
				

		}


	
	
	
	yr_compiler_get_rules(compiler, &rules);
	



	std::string filename = "D:\\Temp\\1.bin";
	std::vector<uint8_t> str;
	
	if (std::ifstream is{ filename, std::ios::binary }) {
		is.seekg(0, std::ios::end);
		auto size = is.tellg();
		//std::string str(size, '\0'); // construct string to stream size
		str.resize(size);
		is.seekg(0);
		if (is.read((char*)str.data(), size))
		{

			//  std::filesystem::remove(dir_entry.path());
		}
	}
	YR_SCANNER* scaner;
	yr_scanner_create(rules, &scaner);
	//auto dd=yr_scanner_scan_mem(scaner, str.data(), str.size());

	int result =yr_rules_scan_file(rules, "D:\\Temp\\yara-readthedocs-io-en-latest.pdf", SCAN_FLAGS_REPORT_RULES_MATCHING, (YR_CALLBACK_FUNC)callback_function, nullptr, 0);
	if (result != ERROR_SUCCESS) {
		std::cerr << "Scan failed" << std::endl;
		yr_rules_destroy(rules);
		yr_finalize();
		return result;
	}
	//auto ff = yr_scanner_scan_file(scaner, "D:\\Temp\\1.bin");
	//yr_rules_scan_mem(rules, (uint8_t*)str.data(), str.size(), 0, (YR_CALLBACK_FUNC)my_callback_search, nullptr, 0);
	
	yr_rules_save(rules, "D:\\Temp\\rules.yara");
	yr_compiler_destroy(compiler);
	yr_rules_destroy(rules);

	yr_finalize();
	return 0;
}
